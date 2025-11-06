  param (
    [string]$token = $(Read-Host "`nInput the node registration token, please"),
    [string]$api_host = $(Read-Host "`nInput the codefresh installation hostname, please. Default: g.codefresh.io"),
    [string]$docker_root = $(Read-Host "`nInput the docker root path, please. It is recommended to have it on a separate disk. Default: C:/ProgramData/Docker"),
    [string]$ip = $(Read-Host "`nInput the IP of the node. It must be reachable by the CF application")
 )

function writeEmbeddedRegScript() {
    $global:script_path = ($pwd.Path + '\cloud-init.sh').Replace('\', '/');

    $script_contents = @'
#!/bin/bash
#
echo -e "The script installs docker and registers node in codefresh.io \n\
Please ensure:
  1. Supported systems: Ubuntu 14+ | Debian 8+ | RHEL/Centos/Oracle 7+
  2. The script is running by admin user ( root or by sudo $(basename $0) )
  3. Port tcp:2376 should be open for codefresh whitelist addresses

"

#---
fatal() {
   echo "ERROR: $1"
   exit 1
}

while [[ $1 =~ ^(-(h|g|t|y)|--(api-host|gen-certs|docker-root|token|yes|ip|iface|dns-name)) ]]
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
    --iface)
        ## Net interface to take IP
        IFACE="$value"
        shift
      ;;
    --dns-name)
        DNSNAME="$value"
        shift
      ;;
  esac
  shift # past argument or value
done

if [[ -z $API_HOST ]]; then
  API_HOST=g.codefresh.io
fi

TOKEN=${TOKEN:-$1}
[[ -z "$TOKEN" ]] && fatal "Missing token"

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

TMPDIR=/tmp/codefresh
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
VALIDATE_STATUS=$(curl -ksSL -d @${TMPDIR}/validate_req.json  -H "Content-Type: application/json" -H "x-codefresh-api-key: ${TOKEN}" \
      -o ${TMP_VALIDATE_RESPONCE_FILE} -D ${TMP_VALIDATE_HEADERS_FILE} -w '%{http_code}' https://${API_HOST}/api/nodes/validate )
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
  openssl req -subj "/CN=*.codefresh.io" -new -key $SRV_TLS_KEY -out $SRV_TLS_CSR  || fatal "Failed to generate openssl csr "
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
  SIGN_STATUS=$(curl -ksSL -d @${TMPDIR}/sign_req.json -H "Content-Type: application/json" -H "x-codefresh-api-key: ${TOKEN}" -H "Expect: " \
        -o ${TMP_CERTS_FILE_ZIP} -D ${TMP_CERTS_HEADERS_FILE} -w '%{http_code}' https://${API_HOST}/api/nodes/sign )

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

fi

    echo "--- Configuring the docker daemon..."

    DOCKERD_CFG="{\"hosts\":[\"tcp://0.0.0.0:2376\",\"npipe:////./pipe/codefresh/docker_engine\",\"npipe://\"],\"tlsverify\":true,\"tlscacert\":\"C:/cygwin64/etc/ssl/codefresh/cf-ca.pem\",\"tlscert\":\"C:/cygwin64/etc/ssl/codefresh/cf-server-cert.pem\",\"tlskey\":\"C:/cygwin64/etc/ssl/codefresh/cf-server-key.pem\",\"data-root\":\"$DOCKER_ROOT\",\"log-opts\":{\"max-size\":\"50m\"}}"

    mkdir C:/ProgramData/Docker/ 2>/dev/null
    mkdir C:/ProgramData/Docker/config 2>/dev/null
    echo $DOCKERD_CFG > C:/ProgramData/Docker/config/daemon.json

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
  REGISTER_STATUS=$(curl -ksSL -d @${TMPDIR}/register_data.json -H "Content-Type: application/json" -H "x-codefresh-api-key: ${TOKEN}" \
        -o ${TMPDIR}/register.out -D ${TMPDIR}/register_responce_headers.out -w '%{http_code}' https://${API_HOST}/api/nodes/register )


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
}

function ensureDaemonCertsACL() {
   $docker_config_path = "C:\ProgramData\Docker\config\daemon.json";
   $certs_path = "C:\cygwin64\etc\ssl\codefresh";

   $newacl = Get-Acl -Path $docker_config_path;
   Get-ChildItem -Path $certs_path -Recurse -Force | ForEach-Object { Set-Acl $_.FullName -AclObject $newacl };
}

function configureNode() {
    if (!$token) {
        throw "The token hasn't been provided, stopping execution...";
    }

    if (!$api_host) {
        Write-Host "`nThe hostname hasn't been provided, using the default value: g.codefresh.io" -ForegroundColor Yellow;
        $api_host = "g.codefresh.io";
    }
    if (!$docker_root) {
        Write-Host "`ndocker-root hasn't been provided, using the default value: C:/ProgramData/Docker" -ForegroundColor Yellow;
        $docker_root = "C:/ProgramData/Docker";
    } else {
        $docker_root = $docker_root.replace("\","/")
    }

    writeEmbeddedRegScript

    Write-Host 'Running the node installation shell script...';

    C:\cygwin64\bin\bash -l -c "sed -i 's/\r$//' $script_path" # necessary for cygwin

    Write-Host "Passing control to bash, command is C:\cygwin64\bin\bash -l -c '$script_path --token $token --api-host $api_host --docker-root $docker_root --ip $ip'";
    C:\cygwin64\bin\bash -l -c "$script_path --token $token --api-host $api_host --docker-root $docker_root --ip $ip";

    if (!$?) {
        throw "`nError during the node configuration";
    }

    ensureDaemonCertsACL

    Write-Host "Restarting docker daemon to apply the new configuration" -ForegroundColor Yellow
    net stop docker
    net start docker

    rm -Force $script_path
}

configureNode
