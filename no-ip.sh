#!/bin/bash
#
#  no-ip bash script/1.0 by ENA.
#
#  script update DDNS registry in NO-IP https://my.noip.com/
#

# https://gist.github.com/mohanpedala/1e2ff5661761d3abd0385e8223e16425
#set -eo pipefail

# inicialización de variables.
USERNAME=""
PASSWORD=""
HOSTNAME=""
LOGFILE="/var/log/no-ip.log"
DETECTIP=""
IP=""
NEWIP=""
RESULT=""
INTERVAL=0
CONFIG=""
DATE=$(date)

# Functions
writeLog () {
        local  log=$1
        local  write=1
	if  [ -n "$LOGFILE" ]; then
                if [ ! -f "$LOGFILE" ]; then
                        touch "$LOGFILE"
                fi
#		if [ $DEBUG -eq 1 ]; then
                	echo "$DATE --  $log" | tee -a $LOGFILE
#		fi
        fi
}

valid_ip() {
# function to validate IP address.
# http://www.linuxjournal.com/content/validating-ip-address-bash-script
	local  ip=$1
    	local  stat=1

    	if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        	OIFS=$IFS
	        IFS='.'
        	ip=($ip)
	        IFS=$OIFS
        	[[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
	        stat=$?
    	fi
    	return $stat
}

function cmd_exists() {
    	command -v "$1" > /dev/null 2>&1
}

function http_get() {
# API request:  https://www.noip.com/integrate/request
# GET /nic/update?hostname=mytest.example.com&myip=192.0.2.25 HTTP/1.1
# Host: dynupdate.no-ip.com
# Authorization: Basic base64-encoded-auth-string
# User-Agent: Company DeviceName-Model/FirmwareVersionNumber maintainer-contact@example.com
# IMPORTANT: USERNAME not work with e-mail.

	USERAGENT="no-ip bash script/1.0 $USERNAME"
	REQUEST_URL="http://$USERNAME:$PASSWORD@dynupdate.no-ip.com/nic/update?hostname=$HOSTNAME&myip=$NEWIP"

#      	curl --verbose -s --user-agent "$USERAGENT" $REQUEST_URL
       	curl -s --user-agent "$USERAGENT" $REQUEST_URL
}

function get_response() {
    local host
    local response
    local response_a
    local response_b

    	host="$1"
    	response=$(echo "$2" | tr -cd "[:print:]")
    	response_a=$(echo "$response" | awk '{ print $1 }')

    	case $response_a in
        	"good")
            		response_b=$(echo "$response" | awk '{ print $2 }')
            		writeLog "(good) [$host] DNS hostname successfully updated to $response_b."
            	;;
        	"nochg")
            		response_b=$(echo "$response" | awk '{ print $2 }')
            		writeLog "(nochg) [$host] IP address is current: $response_b; no update performed."
            	;;
        	"nohost")
            		writeLog "(nohost) [$host] Hostname supplied does not exist under specified account. Revise config file."
            	;;
        	"badauth")
            		writeLog "(badauth) [$host] Invalid username password combination."
            	;;
        	"badagent")
            		writeLog "(badagent) [$host] Client disabled - No-IP is no longer allowing requests from this update script."
            	;;
        	'!donator')
            		writeLog '(!donator)'" [$host] An update request was sent including a feature that is not available."
            	;;
        	"abuse")
            		writeLog "(abuse) [$host] Username is blocked due to abuse."
            	;;
        	"911")
            		writeLog "(911) [$host] A fatal error on our side such as a database outage. Retry the update in no sooner than 30 minutes."
            	;;
        	"")
            		writeLog "(empty) [$host] No response received from No-IP. This may be due to rate limiting or a server-side problem."
            	;;
        	*)
            		writeLog "(error) [$host] Could not understand the response from No-IP. The DNS update server may be down."
            	;;
    	esac
	return 0
}
#------------------------------------------------------------------------------------------------------------------------------------
# Begin Read config file.
if [ -f "/etc/no-ip/no-ip.conf" ]
then
	CONFIG="/etc/no-ip/no-ip.conf"
        while read line
        do
                echo $line
                case $line in
                        user=*)
                        USERNAME="${line#*=}"
                        ;;
                        password=*)
                        PASSWORD="${line#*=}"
                        ;;
#                        logfile=*)
#                        LOGFILE="${line#*=}"
#                        ;;
                        hostname=*)
                        HOSTNAME="${line#*=}"
                        ;;
                        detectip=*)
                        DETECTIP="${line#*=}"
                        ;;
                        ip=*)
                        IP="${line#*=}"
                        ;;
#                        interval=*)
#                        INTERVAL="${line#*=}"
#                        ;;
                        *)
                        ;;
                esac
        done < "$CONFIG"
else
	writeLog "File configuration /etc/no-ip/no-ip.conf not found."
        exit 10
fi

# check important variables of file configuration /etc/no-ip/no-ip.conf
if [ -z "$USERNAME" ]; then
	writeLog "No existe la variable username en fichero configuración /etc/no-ip/no-ip.conf. ex: username=ppillo"
	exit 10
fi
if [ -z "$PASSWORD" ]; then
	writeLog "No existe la variable password en fichero configuración /etc/no-ip/no-ip.conf. ex: password=ppillo"
	exit 20
fi
if [ -z "$HOSTNAME" ]; then
	writeLog "No existe la variable hostname en fichero configuración /etc/no-ip/no-ip.conf. ex: hostname=pve.ddns.net"
	exit 30
fi
if [ -n "$DETECTIP" ]; then  #-n tests the following argument and evaluates to true if it is not an empty string.
	x=3
	while [ $x -ne 0 ]
	do
		NEWIP=$(wget -qO- "http://myexternalip.com/raw")
		if valid_ip $NEWIP; then 
			writeLog "Detect external IP = $NEWIP"
			break
		else
			writeLog "Could not detect external IP, sleep $x minutes"
			sleep 1m 
			((x--))
		fi
	done	

	if !( valid_ip $NEWIP ); then
       		writeLog "Could not detect external IP with http://myexternalip.com/raw, Try: wget -qO- http://myexternalip.com/raw"
		exit 40
	fi
fi

if [ "$IP" == "$NEWIP" ]; then
	writeLog "The IP $NEWIP is the same as configuration file. No change had made..!"
	exit 0 
else
	RESPONSE=$(http_get)
#	writeLog $RESPONSE
	OIFS=$IFS
	IFS=$'\n'
	SPLIT_RESPONSE=( $(echo "$RESPONSE" | grep -o '[0-9a-z!]\+\( [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)\?') )
	IFS=','
	SPLIT_HOST=( $HOSTNAME )
	IFS=$OIFS
	echo ${SPLIT_HOST[@]}
	for index in "${!SPLIT_HOST[@]}"; do
    		get_response "${SPLIT_HOST[index]}" "${SPLIT_RESPONSE[index]}"
	done

# change IP in the config file.
	sed -ir "s/^[#]*\s*ip=.*/ip=$NEWIP/" $CONFIG
fi
exit 0
