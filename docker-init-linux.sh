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

while [[ $1 =~ ^(-(h|g|t|y)|--(api-host|gen-certs|token|yes|ip|iface|dns-name|install|no-install|restart|no-restart)) ]]
do
  key=$1
  value=$2

  case $key in
    -y|--yes)
        YES="true"
      ;;
    -h|--api-host)
      API_HOST="$value"
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
        read -p "IP of the node - default ${DEFAULT_IP}: " IP
    fi

    if [[ -z "$IP" ]]; then
      IP="${DEFAULT_IP}"
    fi
fi

if [[ -z "$DNSNAME" && ! "$YES" == 'true' ]]; then
  read -p "Enter DNS name of the node (optional): " DNSNAME
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

echo -e "\n------------------\n Installing packages ... "
source /etc/os-release || fatal  "Operating system is not supported"
if [[ "$ID" =~ 'rhel' || "$ID_LIKE" =~ 'rhel' ]]; then
  INSTALLER="yum install -y"
  INST_CHECK="rpm -q"
  PKGLIST=( openssl zip unzip gawk curl )
elif [[ "$ID" =~ 'debian' || "$ID_LIKE" =~ 'debian' ]]; then
  INSTALLER="apt-get install -y"
  INST_CHECK="dpkg -l"
  PKGLIST=( openssl zip unzip gawk curl )
  apt-get update -y
else
  fatal "Operating system is not supported"
fi

PKGLIST_INSTALL=""
for ii in "${PKGLIST[@]}"
do
   $INST_CHECK $ii >/dev/null 2>&1
   if [[ $? != 0 ]]; then
      echo "Package $ii will be installed "
      PKGLIST_INSTALL="$PKGLIST_INSTALL $ii"
   else
      echo "Package $ii is already installed "
   fi
done

if [[ -n "$PKGLIST_INSTALL" ]]; then
   echo "Running $INSTALLER $PKGLIST_INSTALL ..."
   $INSTALLER $PKGLIST_INSTALL || fatal "Failed to install packages"
fi

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
echo "{\"ip\": \"${IP}\", \"serverAuthIps\": \"${SERVER_AUTH_IPS}\", \"dnsname\": \"${DNSNAME}\", \
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




if [[ $INSTALL_DOCKER == 'true' ]]; then
   echo -e "\n------------------\nInstalling docker ... "
   curl -sSL https://get.docker.com/ | sudo CHANNEL=stable sh -
   EXIT_CODE=$?
   if [[ $EXIT_CODE != 0 && $EXIT_CODE != 130 ]] || ! which docker ; then
      echo -e "\n---- ERROR: Docker installation from https://get.docker.com/ failed - $EXIT_CODE , please fix and rerun the script"
      exit 1
   fi
fi
   
   mkdir -p /var/run/codefresh
   DOCKER_OPTS=" -H unix:///var/run/docker.sock -H unix:///var/run/codefresh/docker.sock -H tcp://0.0.0.0:2376 \
--tlsverify --tlscacert=${SRV_TLS_CA_CERT} --tlscert=${SRV_TLS_CERT} --tlskey=${SRV_TLS_KEY} --label io.codefresh.node.name=${CF_NODE_NAME} \
${ADDITIONAL_DOCKER_OPTS} "

   SET_DOCKER_OPTS="# Generated by codefresh-init
#
mkdir -p /var/run/codefresh
DOCKER_OPTS=\"${DOCKER_OPTS}\""
   
   echo "Setting $SET_DOCKER_OPTS"
   TMP_DOCKER_OPTS=${TMPDIR}/docker-opts
   echo -e "${SET_DOCKER_OPTS}" > ${TMP_DOCKER_OPTS}

   diff /etc/default/docker ${TMP_DOCKER_OPTS}
   if [[ $? == 0 ]]; then
       echo "Docker OPTS are not changed"
       RESTART_DOCKER=${RESTART_DOCKER:-'false'}
   else
       echo "Docker OPTS has been changed"
       if [[ -f /etc/default/docker ]]; then
         cp -f /etc/default/docker ${TMPDIR}/docker-opts.cfbak_$(date "+%y-%m-%d_%Hh%Mm%Ss")
       fi
       cp -f ${TMP_DOCKER_OPTS} /etc/default/docker

       # Apply environment for systemctl
       if [[ -d /etc/systemd/system ]] && which systemctl &> /dev/null; then
         TMP_SYSTEMCTL_DOCKER=${TMPDIR}/systemctl_docker.conf
         SYSTEMCTL_DOCKER="# Generated by codefresh-init
#
[Service]
EnvironmentFile=-/etc/default/docker
ExecStart=
ExecStartPre=-/bin/mkdir -p /var/run/codefresh
ExecStart=/usr/bin/dockerd \$DOCKER_OPTS
"
         echo -e "$SYSTEMCTL_DOCKER" > $TMP_SYSTEMCTL_DOCKER
         diff /etc/systemd/system/docker.service.d/docker.conf ${TMP_SYSTEMCTL_DOCKER}
         if [[ $? != 0 ]]; then
            mkdir -p /etc/systemd/system/docker.service.d
            cp -af /etc/systemd/system/docker.service.d/docker.conf ${TMPDIR}/systemctl_docker.conf.cfbak_$(date "+%y-%m-%d_%Hh%Mm%Ss")
            cp -f ${TMP_SYSTEMCTL_DOCKER} /etc/systemd/system/docker.service.d/docker.conf
            systemctl daemon-reload
         fi
       fi
       RESTART_DOCKER=${RESTART_DOCKER:-'true'}
   fi

   if [[ ${RESTART_DOCKER} == 'true' ]]; then
       echo "Restarting docker"
       service docker restart && sleep 3
   fi
   docker ps > /dev/null
   if [[ $? != 0 ]]; then
      service docker restart && sleep 3
      docker ps > /dev/null || fatal "Docker daemon failed to start. Please review the messages above, fix and restart the script"
   fi

   echo "\n---------------------\nStarting cadvisor ... "
   docker run --name=cadvisor --publish=720:8080 --restart always  --detach=true -e SERVICE_IGNORE=True \
      --volume=/:/rootfs:ro --volume=/var/run:/var/run:rw --volume=/sys:/sys:ro --volume=/var/lib/docker/:/var/lib/docker:ro   \
      -l io.codefresh.owner=codefresh -l io.codefresh.visibility=internal google/cadvisor:v0.26.3

   
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

  echo "Registration request completed with HTTP_STATUS_CODE=$REGISTER_STATUS"
  if [[ $REGISTER_STATUS == 200 ]]; then
     echo -e "Node has been successfully registered with Codefresh\n------"
  else
     echo "ERROR: Failed to register docker node with Codefresh"
     [[ -f ${TMPDIR}/register.out ]] && cat ${TMPDIR}/register.out
     echo -e "\n----\n"
     exit 1
  fi   



