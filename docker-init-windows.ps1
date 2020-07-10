param (
  [Parameter(Mandatory=$true)][string]$api_host,
  [Parameter(Mandatory=$true)][string]$token,
  [Parameter(Mandatory=$true)][string]$dns_name,
  [Parameter(Mandatory=$true)][string]$ip
)

Update-StorageProviderCache -DiscoveryLevel Full
$offlineDisks =  Get-Disk | Where-Object PartitionStyle -Eq 'RAW'
$disksCount = $offlineDisks.Number.Count
$docker_root = "D:/docker"

if (($disksCount -eq 0) -and (!(Test-Path D:))) {$dockerRoot = "C:/ProgramData/docker"}
Elseif ($disksCount -gt 1) {
  $PhysicalDisks = Get-StorageSubSystem -FriendlyName "Windows Storage*" | Get-PhysicalDisk -CanPool $True
  New-StoragePool -FriendlyName CodefreshData -StorageSubsystemFriendlyName "Windows Storage*" -PhysicalDisks $PhysicalDisks
  $allowedDiskSize = (Get-StoragePool -isPrimordial $False).Size
  New-VirtualDisk -FriendlyName CodefreshVirtualDisk -Size $allowedDiskSize -StoragePoolFriendlyName CodefreshData -ProvisioningType Thin
  Initialize-Disk -VirtualDisk (Get-VirtualDisk -FriendlyName CodefreshVirtualDisk) -passthru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume
} 
ElseIf ($disksCount -eq 1) {
  Initialize-Disk -Number 1 -PartitionStyle MBR
  New-Partition -DiskNumber 1 -UseMaximumSize -AssignDriveLetter | Format-Volume -NewFileSystemLabel "Drive" -FileSystem NTFS
}

$release_id = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId
$script_path = ($pwd.Path + '\cloud-init.sh').Replace('\', '/');

$script_contents = @'
#!/bin/bash
#
echo -e "The script installs docker and registers node in codefresh.io \n\
Please ensure:
  1. Supported systems: Ubuntu 14+ | Debian 8+ | RHEL/Centos/Oracle 7+
  2. The script is running by admin user ( root or by sudo $(basename $0) )
  3. Port tcp:2376 should be open for codefresh whitelist addresses

" 

API_HOST=${API_HOST:-https://g.codefresh.io/api/nodes}

#---
fatal() {
   echo "ERROR: $1"
   exit 1
}

while [[ $1 =~ ^(-(h|g|t|y)|--(api-host|gen-certs|release-id|docker-root|token|yes|ip|iface|dns-name|install|no-install|restart|no-restart)) ]]
do
  key=$1
  value=$2

  case $key in
    -y|--yes)
        YES="true"
      ;;
    -h|--api-host)
      API_HOST="$value"
      shift
      ;;
    -g|--gen-certs)
        GENERATE_CERTS="true"
      ;;
    -t|--token)
        TOKEN="$value"
        shift
      ;;
    --ip)
        ## IP Address
        IP="$value"
        shift
      ;;
    --docker-root)
        DOCKER_ROOT="$value"
        shift
      ;;
    --release-id)
        RELEASE_ID="$value"
        shift
      ;;
    --iface)
        ## Net interface to take IP
        IFACE="$value"
        shift
      ;;
    --dns-name)
        DNSNAME="$value"
        shift
      ;;
    --install)
        INSTALL_DOCKER="true"
      ;;
    --no-install)
        INSTALL_DOCKER="false"
      ;;
    --restart)
        RESTART_DOCKER="true"
      ;;
    --no-restart)
        RESTART_DOCKER="false"
      ;;
  esac
  shift # past argument or value
done


TOKEN=${TOKEN:-$1}
[[ -z "$TOKEN" ]] && fatal "Missing token"

if [[ -z $INSTALL_DOCKER ]]; then
    INSTALL_DOCKER=$(! which docker &> /dev/null && echo 'true' || echo 'false')
fi

GENERATE_CERTS="true"

if [[ -z "$IP" ]]; then
    echo "Determine default IP ..."

    if [[ -n "$IFACE" && ! "$IFACE" == 'public' ]]; then
       DEFAULT_IP=$(/sbin/ip -4 -o addr show scope global | awk -v iface=$IFACE '$2==iface { sub(/\/.*/,"", $4) ; print $4 }')
    else
        ## Get Public IP
        cnt=0
        while [[ $cnt -lt 20 ]]
        do
           DEFAULT_IP=$(timeout 3 curl ident.me 2>/dev/null || timeout 3 curl ipecho.net/plain 2>/dev/null || timeout 3 curl whatismyip.akamai.com 2>/dev/null)
           [[ -n "${DEFAULT_IP}" ]] && break
           (( cnt ++ ))
           sleep 3
        done
    fi

    if [[ ! "$YES" == 'true' ]]; then
        echo -e "Enter the IP Address of the node for incoming connection from Codefresh (port tcp:2376)
    ${DEFAULT_IP} - default
$(/sbin/ip -4 -o addr show scope global | awk '{gsub(/\/.*/,"",$4); print "    "$4}' | sort)\n"
    fi

    if [[ -z "$IP" ]]; then
      IP="${DEFAULT_IP}"
    fi
fi

DNSNAME=${DNSNAME:-$IP}

TMPDIR=/tmp/codefresh/
TMP_VALIDATE_RESPONCE_FILE=$TMPDIR/validate-responce
TMP_VALIDATE_HEADERS_FILE=$TMPDIR/validate-headers.txt

TMP_CERTS_FILE_ZIP=$TMPDIR/cf-certs.zip
TMP_CERTS_HEADERS_FILE=$TMPDIR/cf-certs-response-headers.txt
CERTS_DIR=/etc/ssl/codefresh
SRV_TLS_KEY=${CERTS_DIR}/cf-server-key.pem
SRV_TLS_CSR=${CERTS_DIR}/cf-server-cert.csr
SRV_TLS_CERT=${CERTS_DIR}/cf-server-cert.pem
SRV_TLS_CA_CERT=${CERTS_DIR}/cf-ca.pem

mkdir -p $TMPDIR $CERTS_DIR

echo -e "\n------------------\nValidate node ... "
echo "{\"ip\": \"$IP\", \"dnsname\": \"${DNSNAME}\"}" > ${TMPDIR}/validate_req.json
VALIDATE_STATUS=$(curl -sSL -d @${TMPDIR}/validate_req.json  -H "Content-Type: application/json" -H "x-codefresh-api-key: ${TOKEN}" \
      -o ${TMP_VALIDATE_RESPONCE_FILE} -D ${TMP_VALIDATE_HEADERS_FILE} -w '%{http_code}' $API_HOST/validate )
echo "Validate Node request completed with HTTP_STATUS_CODE=$VALIDATE_STATUS"
if [[ $VALIDATE_STATUS != 200 ]]; then
   echo "ERROR: Node Validation failed"
   if [[ -f ${TMP_VALIDATE_RESPONCE_FILE} ]]; then
     mv ${TMP_VALIDATE_RESPONCE_FILE} ${TMP_VALIDATE_RESPONCE_FILE}.error
     cat ${TMP_VALIDATE_RESPONCE_FILE}.error
   fi
   exit 1
fi

echo "Validate responce: "
cat ${TMP_VALIDATE_RESPONCE_FILE}
source ${TMP_VALIDATE_RESPONCE_FILE}

[[ -z "$CF_NODE_NAME" ]] && fatal "Validation failed - cannot find CF_NODE_NAME"

echo "CF_NODE_NAME - $CF_NODE_NAME"
echo -e "\n------------------\nGenerating docker server tls certificates ... "
if [[ "$GENERATE_CERTS" == 'true' || ! -f ${SRV_TLS_CERT} || ! -f ${SRV_TLS_KEY} || ! -f ${SRV_TLS_CA_CERT} ]]; then
  openssl genrsa -out $SRV_TLS_KEY 4096 || fatal "Failed to generate openssl key " 
  openssl req -subj "/CN=${CF_NODE_NAME}.codefresh.io" -new -key $SRV_TLS_KEY -out $SRV_TLS_CSR  || fatal "Failed to generate openssl csr "
  GENERATE_CERTS=true
  CSR=$(sed ':a;N;$!ba;s/\n/\\n/g' ${SRV_TLS_CSR})
else  
  echo "Certificates already exist in $CERTS_DIR - Do not generate certificates"
fi

SERVER_AUTH_IPS=${IP},$(/sbin/ip -4 -o addr show scope global | awk '$2 !~ "br-*" { sub(/\/.*/,"", $4) ; print $4 }'  | paste -s -d, -)
echo "{\"ip\": \"${IP}\", \"serverAuthIps\": \"${IP}\", \"dnsname\": \"${DNSNAME}\", \
   \"csr\": \"${CSR}\" }" > ${TMPDIR}/sign_req.json

if [[ $GENERATE_CERTS == 'true' ]]; then
  rm -fv ${TMP_CERTS_HEADERS_FILE} ${TMP_CERTS_FILE_ZIP}
  SIGN_STATUS=$(curl -sSL -d @${TMPDIR}/sign_req.json -H "Content-Type: application/json" -H "x-codefresh-api-key: ${TOKEN}" -H "Expect: " \
        -o ${TMP_CERTS_FILE_ZIP} -D ${TMP_CERTS_HEADERS_FILE} -w '%{http_code}' $API_HOST/sign )
        
  echo "Sign request completed with HTTP_STATUS_CODE=$SIGN_STATUS"
  if [[ $SIGN_STATUS != 200 ]]; then
     echo "ERROR: Cannot sign certificates"
     if [[ -f ${TMP_CERTS_FILE_ZIP} ]]; then
       mv ${TMP_CERTS_FILE_ZIP} ${TMP_CERTS_FILE_ZIP}.error
       cat ${TMP_CERTS_FILE_ZIP}.error
     fi
     exit 1
  fi
  unzip -o -d ${CERTS_DIR}/  ${TMP_CERTS_FILE_ZIP} || fatal "Failed to unzip certificates to ${CERTS_DIR} "
  RESTART_DOCKER=${RESTART_DOCKER:-'true'}


  # Generate internal certs (ICA)
    ICA_PASS=$RANDOM
    ICA_PASS_FILE=${CERTS_DIR}/i-capass

    ICA_KEY=${CERTS_DIR}/i-ca-key.pem
    ICA=${CERTS_DIR}/i-ca.pem
    IEXTFILE=${CERTS_DIR}/i-extfile
    ICERT_CSR=${CERTS_DIR}/i-cert.csr
    ICERT_KEY=${CERTS_DIR}/i-key.pem
    ICERT=${CERTS_DIR}/i-cert.pem

    ICA_SUBJECT="/CN=internal.cf-cd.com"

    echo "CA_PASS = $ICA_PASS " > "$ICA_PASS_FILE"

    echo "--- Generate internal ca-key.pem"
    openssl genrsa -aes256 -out "$ICA_KEY" -passout pass:"$ICA_PASS"

    echo "--- Generate internal ca.pem"
    openssl req -new -x509 -days 1096 -key "$ICA_KEY" -sha256 -out "$ICA" -subj "${ICA_SUBJECT}" -passin pass:"$ICA_PASS"


    echo "--- Generate internal key.pem"
    openssl genrsa -out "$ICERT_KEY" 4096

    echo "--- generate internal csr "
    openssl req -subj "${ICA_SUBJECT}" -sha256 -new -key "${ICERT_KEY}" -out "${ICERT_CSR}"

    echo "--- create internal ca extfile"
    echo "extendedKeyUsage=clientAuth" > "$IEXTFILE"

    echo "--- sign internal certificate ${ICERT} "
    openssl x509 -req -days 1096 -sha256 -in "$ICERT_CSR" -CA "$ICA" -CAkey "$ICA_KEY" \
    -CAcreateserial -out "$ICERT" -extfile "$IEXTFILE" -passin pass:"$ICA_PASS" || fatal "Failed to sign internal certificate"

    echo "--- Appending Internal CA file to dockerd tlscacert ${SRV_TLS_CA_CERT} "
    cat ${ICA} >> ${SRV_TLS_CA_CERT}

fi

    echo "--- Configuring the docker daemon..."
    
    DOCKERD_CFG="{\"hosts\":[\"tcp://0.0.0.0:2376\",\"npipe:////./pipe/codefresh/docker_engine\",\"npipe://\"],\"tlsverify\":true,\"tlscacert\":\"C:/cygwin64/etc/ssl/codefresh/cf-ca.pem\",\"tlscert\":\"C:/cygwin64/etc/ssl/codefresh/cf-server-cert.pem\",\"tlskey\":\"C:/cygwin64/etc/ssl/codefresh/cf-server-key.pem\",\"graph\":\"$DOCKER_ROOT\",\"log-opts\":{\"max-size\":\"50m\"}}"

    mkdir C:/ProgramData/Docker/ 2>/dev/null
    mkdir C:/ProgramData/Docker/config 2>/dev/null
    echo $DOCKERD_CFG > C:/ProgramData/Docker/config/daemon.json

 if [[ ${RESTART_DOCKER} == 'true' ]]; then
       echo "Restarting docker"
       net stop docker
       net start docker
       sleep 3
   fi
   docker ps > /dev/null
   if [[ $? != 0 ]]; then
      service docker restart && sleep 3
      docker ps > /dev/null || fatal "Docker daemon failed to start. Please review the messages above, fix and restart the script"
fi

    echo "clonning images"
    docker pull codefresh/cf-container-logger:windows-$RELEASE_ID
    docker pull codefresh/cf-docker-pusher:windows-$RELEASE_ID
    docker pull codefresh/cf-docker-puller:windows-$RELEASE_ID
    docker pull codefresh/cf-docker-builder:windows-$RELEASE_ID
    docker pull codefresh/cf-git-cloner:windows-$RELEASE_ID
    docker pull codefresh/cf-compose:windows-$RELEASE_ID
    docker pull codefresh/cf-deploy-kubernetes:windows-$RELEASE_ID
    docker pull codefresh/fs-ops:windows-$RELEASE_ID


echo -e "\n------------------\nRegistering Docker node ... "
   
   CPU_CORES=$(cat /proc/cpuinfo | grep "^processor" | wc -l)
   CPU_MODEL=$(cat /proc/cpuinfo | awk -F ': ' '/model name/{print $2}' | head -n1)
   RAM="$(free -m | awk '/Mem:/{print $2}')M"
   SYSTEM_DISK=$(/bin/df -h / | awk 'NR==2{print $2}')
   CREATION_DATE=$(date +"%Y-%m-%d %H:%M")
   OS_ID=$(. /etc/os-release 2>/dev/null && echo ${ID} || echo linux)
   OS_VERSION=$(. /etc/os-release 2>/dev/null && echo ${VERSION_ID} || echo "")
   OS_NAME=$(. /etc/os-release 2>/dev/null && echo ${PRETTY_NAME:-$ID} || echo linux)
   HOSTNAME=$(hostname)

   SYSTEM_DATA="{\"cpu_cores\": \"${CPU_CORES}\",
\"cpu_model\": \"${CPU_MODEL}\",
\"ram\": \"${RAM}\",
\"system_disk\": \"${SYSTEM_DISK}\",
\"os_id\": \"$OS_ID\",
\"os_version\": \"$OS_VERSION\",
\"os_name\": \"$OS_NAME\",
\"hostname\": \"$HOSTNAME\",
\"creation_date\": \"${CREATION_DATE}\"}"  

   REGISTER_DATA=\
"{\"ip\": \"${IP}\",
  \"dnsname\": \"${DNSNAME}\",
  \"systemData\": "${SYSTEM_DATA}"
  }"
   
  echo "${REGISTER_DATA}" > ${TMPDIR}/register_data.json   
  
  rm -f ${TMPDIR}/register.out ${TMPDIR}/register_responce_headers.out
  REGISTER_STATUS=$(curl -sSL -d @${TMPDIR}/register_data.json -H "Content-Type: application/json" -H "x-codefresh-api-key: ${TOKEN}" \
        -o ${TMPDIR}/register.out -D ${TMPDIR}/register_responce_headers.out -w '%{http_code}' $API_HOST/register ) 


    if grep cf-configurator ${TMPDIR}/register.out &>/dev/null; then
        echo -e "Node has been successfully registered with Codefresh\n------"
        exit 0
    fi
    echo "Registration request completed with HTTP_STATUS_CODE=$REGISTER_STATUS"
    if [[ $REGISTER_STATUS == 200 ]]; then
    echo -e "Node has been successfully registered with Codefresh\n------"
    else
    echo "ERROR: Failed to register docker node with Codefresh"
    [[ -f ${TMPDIR}/register.out ]] && cat ${TMPDIR}/register.out
    echo -e "\n----\n"
    exit 1
    fi
'@

[IO.File]::WriteAllLines($script_path, $script_contents);

Write-Host 'Running the node installation shell script...';

C:\cygwin64\bin\bash -l -c "sed -i 's/\r$//' $script_path" # necessary for cygwin
Write-Host "Passing control to bash, command is C:\cygwin64\bin\bash -l -c '$script_path --token $token --ip $ip --dns-name $dns_name --docker-root $docker_root --release-id $release_id'";
C:\cygwin64\bin\bash -l -c "$script_path --api-host $api_host --token $token --ip $ip --dns-name $dns_name --docker-root $docker_root --release-id $release_id"

#--------- Creating Maintenance Tasks --------------------

$tasksFolder = "C:/cf-maintenance-tasks"
$logsFolder = "$tasksFolder/logs"
mkdir $tasksFolder 2> $null
mkdir $logsFolder 2> $null

function createCacheCleanTask() {
  $cacheCleanerScript_name = "$tasksFolder/cleanCache.ps1"
  $cacheCleanerScriptLog_name = "cleanCache.log"

  $cacheCleanerScript_contents = '
  $keptImagesNumber = 50
  $allImages = $(docker images --format "{{.Repository}}:{{.Tag}}")
  $cfImages = $(docker images --format "{{.Repository}}:{{.Tag}}" --filter label=owner=codefresh.io)

  if ($allImages.count-$cfImages.count -gt $keptImagesNumber) {
    $imagesToDelete = $($allImages[-$($allImages.count-$keptImagesNumber)..-1] | ? {$_ -notin $cfImages} )
    [string[]]$imagesToDelete += $(docker images -q -f "dangling=true" -f "before=$($allImages[$allImages.count-$keptImagesNumber])")
    if ($imagesToDelete) {
      foreach ($image in $imagesToDelete) {
        docker rmi -f $image 2> $null
      }
      [string[]]$allImages += $(docker images -q -f "dangling=true")
      $leftImages = $(docker images).count
      $cleanedImages = $allImages.count - $leftImages
      echo "$(Get-Date) $cleanedImages images cleaned, $leftImages images left"
    } 
  } else {
      echo "$(Get-Date) Nothing to clean, idling..."
  }'
  
  Write-Host "`nAdding Docker image cleaner task...`n";
  [IO.File]::WriteAllLines($cacheCleanerScript_name, $cacheCleanerScript_contents);
  mkdir "$logsFolder/docker_cache_cleaner" 2> $null
  Schtasks /create /f /ru "SYSTEM" /tn "Docker image cleaner" /sc hourly /mo 1 /tr "PowerShell $cacheCleanerScript_name >> $logsFolder/docker_cache_cleaner/`$(Get-Date` -Format` `"MM-dd-yyyy`")_$cacheCleanerScriptLog_name"
}

function createCleanLoggersTask() {
  $loggerCleanerScript_name = "$tasksFolder/loggers_cleaner.sh"
  $loggerCleanerScript_logFolder = "$logsFolder/loggers_cleaner"

  $loggerCleanerScript_contents = @'
  #!/bin/bash

  set -euo pipefail

  # gets a container progressId label value
  function getPID() {
      echo $(docker inspect $1 --format='{{index .Config.Labels "io.codefresh.progressId"}}')
  }

  function findDanglingLoggers() {
      local logger_containers=$(docker ps | grep cf-container-logger | egrep -v '(second|minute)s* ago' | awk '{print $1}')
      local user_containers=$(docker ps | egrep -v cf-container-logger | tail -n +2 | awk '{print $1}')
      
      for l in $logger_containers; do
          local l_pid=$(getPID $l)
          local dangling="true"

          for u in $user_containers; do
              local u_pid=$(getPID $u)

              if [[ "$l_pid" == "$u_pid" ]]; then
                  dangling="false"
                  break
              fi
          done

          if [[ $dangling == "true" ]]; then
              echo $l >> $dangling_loggers;
          fi
      done
  }

  # loops through all logger containers and tries to find
  # user containers with matching progressId, if notthing found - marks logger as dangling
  function cleanDanglingLoggers() {
      echo -e "$(date +"%T") Looking for dangling logger containers...\n"

      dangling_loggers=$(mktemp)
      findDanglingLoggers

      if [[ $(cat $dangling_loggers) ]]; then
          echo -e "The following dangling logger containers will be cleaned:\n"
          cat $dangling_loggers
          for dl in $(cat $dangling_loggers); do
              docker unpause $dl 2>/dev/null || true
              docker rm -f $dl 1>/dev/null
          done
      else
          echo -e "No dangling loggers found\n"
      fi
  }

  cleanDanglingLoggers
'@
  
  Write-Host "`nAdding loggers cleaner task...`n";
  [IO.File]::WriteAllLines($loggerCleanerScript_name, $loggerCleanerScript_contents);
  mkdir "$loggerCleanerScript_logFolder" 2> $null
  Schtasks /create /f /ru "SYSTEM" /tn "Loggers cleaner" /sc hourly /mo 1 /tr "PowerShell -c 'C:\cygwin64\bin\bash.exe -o igncr -l -c $loggerCleanerScript_name' >> $loggerCleanerScript_logFolder/`$(Get-Date` -Format` `"MM-dd-yyyy`")_loggers_cleaner.log"
}

function createCleanRAMTask() {
  Write-Host "`nAdding RAM cleaner task...`n";

  $clearRAMLog_name = "$tasksFolder/clearRAM.log"
  $clearRAMScript_name = "$tasksFolder/clearRAM.ps1"
  $cleanRAMLog_name = "clearRAM.log"

  $clearRAMScript_contents = "
  echo `"`$(Get-Date) Starting Paged Pool memory cleaning...`"
  $tasksFolder/clearRAM.exe workingsets; Start-Sleep 120
  $tasksFolder/clearRAM.exe modifiedpagelist; Start-Sleep 120
  echo `"`$(Get-Date) Paged Pool memory has been dropped to the PageFile successfully`""

  function getCleanerBinary() {
    
    $cleanRAMImage = "codefresh/win-maintainance:$release_id"

    docker pull $cleanRAMImage
    docker create --name tmp $cleanRAMImage
    docker cp tmp:C:/clearRAM.exe "$tasksFolder/"
    docker rm tmp

  }

  getCleanerBinary 1> $null
  [IO.File]::WriteAllLines($clearRAMScript_name, $clearRAMScript_contents);
  mkdir $logsFolder/paged_pool_memory_cleaner 2> $null
  Schtasks /create /f /ru "SYSTEM" /tn "Clean RAM (workaround for a Microsoft bug SAAS-3209)" /sc minute /mo 5 /tr "PowerShell $clearRAMScript_name >> $logsFolder/paged_pool_memory_cleaner/`$(Get-Date` -Format` `"MM-dd-yyyy`")_$cleanRAMLog_name"

}

function createRebootNodeTask() {
  Write-Host "`nAdding Reboot Node task...`n";

  $rebootNodeScript_name = "$tasksFolder/rebootNode.ps1"
  $rebootNodeScriptLog_path = "$tasksFolder/logs"
  $rebootNodeScriptLog_name = "rebootNode.log"

  $rebootNodeScript_contents = '
  $freeRamThreshold = 30

  if (!$token) {
    echo "$(Get-Date) The api token has not been provided, exiting..."
    exit 1
  }

  function getNodeId() {
    $publicIp = (Invoke-WebRequest -UseBasicParsing "http://ifconfig.me/ip").Content

    if (!$publicIp) {
        echo "$(Get-Date) Failed to get node public IP, exiting..."
        exit 1
    }

    $response = $(Invoke-WebRequest -UseBasicParsing -Headers @{"Authorization"="$token"} "https://g.codefresh.io/api/admin/nodes")
    if ($response.StatusCode -eq 401) {
      echo "The authorization token is expired or invalid, exiting..."
      exit 1
    }

    $nodeId = ($response.Content | ConvertFrom-Json) | Where-Object ip -eq $publicIp | Select-Object -ExpandProperty id
    
    if (!$nodeId) {
      echo "$(Get-Date) Failed to get node id"
      exit 1
    }

    return $nodeId
  }

  function pauseNode() {
      $response = $(Invoke-WebRequest -UseBasicParsing -Headers @{"Authorization"="$token"} "https://g.codefresh.io/api/admin/nodes/pause?id=$nodeId")
      if ($response.StatusCode -ne 200) {
        echo "$(Get-Date) Failed to pause the node: $response"
      } else {
          echo "$(Get-Date) The node has been successfully paused..."
          Start-Sleep 30
      }
  }

  function unPauseNode() {
      $response = $(Invoke-WebRequest -UseBasicParsing -Headers @{"Authorization"="$token"} "https://g.codefresh.io/api/admin/nodes/unpause?id=$nodeId")
      if ($response.StatusCode -ne 200) {
          echo "$(Get-Date) Failed to unpause the node: $response"
      } else {
          echo "$(Get-Date) The node has been successfully unpaused..."
      }
  }

  function getFreeMemory() {
      $os = Get-Ciminstance Win32_OperatingSystem
      $freeRam = [math]::Round(($os.FreePhysicalMemory/$os.TotalVisibleMemorySize)*100,2)
      return $freeRam
  }

  function waitWorkflow() {
      echo "$(Get-Date) Starting to wait until the running workflow is finished..."
      $timeout = new-timespan -Minutes 60
      $sw = [diagnostics.stopwatch]::StartNew()

      while ($sw.elapsed -lt $timeout){
          $containersRunning = $(docker ps -q)
          if (!$containersRunning) {
              echo "$(Get-Date) No containers running, breaking"
              return
          }
          echo "$(Get-Date) Containers are still running, keep waiting; free memory is $(getFreeMemory)%..."
          Start-Sleep 60
      }
      echo "$(Get-Date) Timeout occurred, all running containers are considered stuck, proceeding..."
  }

  function executeRebootProcedure() {
      pauseNode
      waitWorkflow
      echo "$(Get-Date) Waiting for the post steps..."
      Start-Sleep 30
      echo "$(Get-Date) Rebooting the node..."
      docker rm -f $(docker ps -aq)
      shutdown -r -f -t 0
  }
  
  echo "`n------------------------------------------`n`n$(Get-Date) Starting the task loop..."

  $nodeId = getNodeId
  
  $rebootOnce = $args[0]
  if ($rebootOnce -eq "once") {
    echo "$(Get-Date) Initiating scheduled reboot..."
    executeRebootProcedure
  } 

  unPauseNode

  # watch free memory in the loop and reboot if the threshold is reached
  while ($true) {
    $freeRam = getFreeMemory
    if ($freeRam -lt $freeRamThreshold) {
        echo "$(Get-Date) Free RAM is $freeRam%, threshold has been reached, initiating node reboot procedure..."
        executeRebootProcedure
    } else {
      echo "$(Get-Date) Free RAM is $freeRam%, idling..."
      Start-Sleep 120
    }
  }'

  $rebootNodeScript_contents = "`$token = `$(cat $tasksFolder/key)" + "`n$rebootNodeScript_contents"

  [IO.File]::WriteAllLines($rebootNodeScript_name, $rebootNodeScript_contents);
  mkdir "$logsFolder/reboots_daily" 2> $null
  mkdir "$logsFolder/reboots_free_ram_threshold" 2> $null
  Schtasks /create /f /ru "SYSTEM" /tn "Reboot once a day (workaround for a Microsoft bug SAAS-3209)" /sc daily /st 04:30 /tr "PowerShell $rebootNodeScript_name` once >> $logsFolder/reboots_daily/`$(Get-Date` -Format` `"MM-dd-yyyy`")_$rebootNodeScriptLog_name"
  Schtasks /create /f /ru "SYSTEM" /tn "Reboot on exceeding free RAM threshold (workaround for a Microsoft bug SAAS-3209)" /sc onstart /tr "PowerShell $rebootNodeScript_name >> $logsFolder/reboots_free_ram_threshold/`$(Get-Date` -Format` `"MM-dd-yyyy`")_$rebootNodeScriptLog_name"
  Get-Scheduledtask -Taskname "Reboot on exceeding*" | Start-ScheduledTask
}

createCacheCleanTask
createCleanLoggersTask
createCleanRAMTask
createRebootNodeTask