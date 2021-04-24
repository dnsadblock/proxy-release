#!/bin/sh

main() {
	OS=$(detect_os)
	GOARCH=$(detect_goarch)
	GOOS=$(detect_goos)
	DNSADBLOCK_BIN=$(bin_location)
	LATEST_RELEASE=$(get_release)

	export dnsadblock_INSTALLER=1

	log_info "OS: $OS"
	log_info "GOARCH: $GOARCH"
	log_info "GOOS: $GOOS"
	log_info "DNSADBLOCK_BIN: $DNSADBLOCK_BIN"
	log_info "LATEST_RELEASE: $LATEST_RELEASE"

	if [ -z "$OS" ] || [ -z "$GOARCH" ] || [ -z "$GOOS" ] || [ -z "$DNSADBLOCK_BIN" ] || [ -z "$LATEST_RELEASE" ]; then
		log_error "Cannot detect running environment."
		exit 1
	fi

	while true; do
		CURRENT_RELEASE=$(get_current_release)
		log_debug "Start install loop with CURRENT_RELEASE=$CURRENT_RELEASE"

		if [ "$CURRENT_RELEASE" ]; then
			if [ "$CURRENT_RELEASE" != "$LATEST_RELEASE" ]; then
				log_debug "dnsadblock is out of date ($CURRENT_RELEASE != $LATEST_RELEASE)"
				menu \
					u "Upgrade dnsadblock from $CURRENT_RELEASE to $LATEST_RELEASE" upgrade \
					c "Configure dnsadblock" configure \
					r "Remove dnsadblock" uninstall \
					e "Exit" exit
			else
				log_debug "dnsadblock is up to date ($CURRENT_RELEASE)"
				menu \
					c "Configure dnsadblock" configure \
					r "Remove dnsadblock" uninstall \
					e "Exit" exit
			fi
		else
			log_debug "dnsadblock is not installed"
			menu \
				i "Install dnsadblock" install \
				e "Exit" exit
		fi
	done
}

install() {
	if type=$(install_type); then
		log_info "Installing dnsadblock..."
		log_debug "Using $type install type"
		if "install_$type"; then
			if [ ! -x "$DNSADBLOCK_BIN" ]; then
				log_error "Installation failed: binary not installed in $DNSADBLOCK_BIN"
				return 1
			fi
			configure
			post_install
			exit 0
		fi
	else
		return $?
	fi
}

upgrade() {
	if type=$(install_type); then
		log_info "Upgrading dnsadblock..."
		log_debug "Using $type install type"
		"upgrade_$type"
	else
		return $?
	fi
}

uninstall() {
	if type=$(install_type); then
		log_info "Uninstalling dnsadblock..."
		log_debug "Using $type uninstall type"
		"uninstall_$type"
	else
		return $?
	fi
}

configure() {
	log_debug "Start configure"
	args=""
	add_arg() {
		for value in $2; do
			log_debug "Add arg -$1=$value"
			args="$args -$1=$value"
		done
	}
	add_arg_bool_ask() {
		arg=$1
		msg=$2
		default=$3
		if [ -z "$default" ]; then
			default=$(get_config_bool "$arg")
		fi
		# shellcheck disable=SC2046
		add_arg "$arg" $(ask_bool "$msg" "$default")
	}
	add_arg config "$(get_config_id)"

	doc "Sending your devices name lets you filter analytics and logs by device."
	add_arg_bool_ask report-client-info 'Report device name?' true

	case $(guess_host_type) in
	router)
		add_arg setup-router true
		;;
	unsure)
		doc "Accept DNS request from other network hosts."
		if [ "$(get_config_bool setup-router)" = "true" ]; then
			router_default=true
		fi
		if [ "$(ask_bool 'Setup as a router?' $router_default)" = "true" ]; then
			add_arg setup-router true
		fi
		;;
	esac

	doc "Make dnsadblock CLI cache responses. This improves latency and reduces the amount"
	doc "of queries sent to our servers."
	if [ "$(guess_host_type)" = "router" ]; then
		doc "Note that enabling this feature will disable dnsmasq for DNS to avoid double"
		doc "caching."
	fi
	if [ "$(get_config cache-size)" != "0" ]; then
		cache_default=true
	fi
	if [ "$(ask_bool 'Enable caching?' $cache_default)" = "true" ]; then
		add_arg cache-size "10MB"

		doc "Instant refresh will force low TTL on responses sent to clients so they rely"
		doc "on CLI DNS cache. This will allow changes on your DnsAdblock config to be applied"
		doc "on your LAN hosts without having to wait for their cache to expire."
		if [ "$(get_config max-ttl)" = "5s" ]; then
			instant_refresh_default=true
		fi
		if [ "$(ask_bool 'Enable instant refresh?' $instant_refresh_default)" = "true" ]; then
			add_arg max-ttl "5s"
		fi
	fi

	if [ "$(guess_host_type)" != "router" ]; then
        doc "Changes DNS settings of the host automatically when dnsadblock is started."
        doc "If you say no here, you will have to manually configure DNS to 127.0.0.1."
        add_arg_bool_ask auto-activate 'Automatically setup local host DNS?' true
    fi
	# shellcheck disable=SC2086

	doc "executing $DNSADBLOCK_BIN install $args"
	asroot "$DNSADBLOCK_BIN" install $args
}

post_install() {
	println
	println "Congratulations! DnsAdBlock is now installed."
	println
	println "To upgrade/uninstall, run this command again and select the approriate option."
	println
	println "You can use the dnsadblock command to control the daemon."
	println "Here is a few important commands to know:"
	println
	println "# Start, stop, restart the daemon:"
	println "dnsadblock start"
	println "dnsadblock stop"
	println "dnsadblock restart"
	println
	println "# Configure the local host to point to dnsadblock or not:"
	println "dnsadblock activate"
	println "dnsadblock deactivate"
	println
	println "# Explore daemon logs:"
	println "dnsadblock log"
	println
	println "# For more commands, use:"
	println "dnsadblock help"
	println
}

install_bin() {
	bin_path=$DNSADBLOCK_BIN
	if [ "$1" ]; then
		bin_path=$1
	fi
	log_debug "Installing $LATEST_RELEASE binary for $GOOS/$GOARCH to $bin_path"
	url="https://github.com/dnsadblock/proxy-release/releases/download/v${LATEST_RELEASE}/dnsadblock_${LATEST_RELEASE}_${GOOS}_${GOARCH}.tar.gz"
	log_debug "Downloading $url"
	asroot mkdir -p "$(dirname "$bin_path")" &&
		curl -sL "$url" | asroot sh -c "tar Ozxf - dnsadblock > \"$bin_path\"" &&
		asroot chmod 755 "$bin_path"
}

upgrade_bin() {
	tmp=$DNSADBLOCK_BIN.tmp
	if install_bin "$tmp"; then
		asroot "$DNSADBLOCK_BIN" uninstall
		asroot mv "$tmp" "$DNSADBLOCK_BIN"
		asroot "$DNSADBLOCK_BIN" install
	fi
	log_debug "Removing spurious temporary install file"
	asroot rm -rf "$tmp"
}

uninstall_bin() {
	asroot "$DNSADBLOCK_BIN" uninstall
	asroot rm -f "$DNSADBLOCK_BIN"
}

install_rpm() {
	asroot curl -s https://api.dnsadblock.com/yum.repo -o /etc/yum.repos.d/dnsadblock.repo &&
		asroot yum install -y dnsadblock
}

upgrade_rpm() {
	asroot yum update -y dnsadblock
}

uninstall_rpm() {
	asroot yum uninstall -y dnsadblock
}

install_zypper() {
	if asroot zypper repos | grep -q dnsadblock >/dev/null; then
		echo "Repository dnsadblock already exists. Skipping adding repository..."
	else
		asroot zypper ar -f https://dl.bintray.com/dnsadblock/rpm/ dnsadblock
	fi
	asroot zypper refresh && asroot zypper in -y dnsadblock
}

upgrade_zypper() {
	asroot zypper up dnsadblock
}

uninstall_zypper() {
	asroot zypper remove -y dnsadblock
	case $(ask_bool 'Do you want to remove the repository from the repositories list?' true) in
	true)
		asroot zypper removerepo dnsadblock
		;;
	esac
}

install_deb() {
	# Fallback on curl, some debian based distrib don't have wget while debian
	# doesn't have curl by default.
	(wget -qO - https://api.dnsadblock.com/repo.gpg || curl -sfL https://api.dnsadblock.com/repo.gpg) | asroot apt-key add - &&
		asroot sh -c 'echo "deb https://dl.bintray.com/dnsadblock/deb stable main" > /etc/apt/sources.list.d/dnsadblock.list' &&
		(test "$OS" = "debian" && asroot apt-get install apt-transport-https || true) &&
		asroot apt-get update &&
		asroot apt-get install -y dnsadblock
}

upgrade_deb() {
	asroot apt-get update &&
		asroot apt-get install -y dnsadblock
}

uninstall_deb() {
	log_debug "Uninstalling deb"
	asroot apt-get upgrade -y dnsadblock
}

install_arch() {
	asroot pacman -Sy yay &&
		yay -Sy dnsadblock
}

upgrade_arch() {
	asroot yay -Suy dnsadblock
}

uninstall_arch() {
	asroot pacman -R dnsadblock
}

install_merlin_path() {
	# Add next to Merlin's path
	mkdir -p /tmp/opt/sbin
	ln -sf "$DNSADBLOCK_BIN" /tmp/opt/sbin/dnsadblock
}

install_merlin() {
	if install_bin; then
		install_merlin_path
	fi
}

uninstall_merlin() {
	uninstall_bin
	rm -f /tmp/opt/sbin/dnsadblock
}

upgrade_merlin() {
	if upgrade_bin; then
		install_merlin_path
	fi
}

install_openwrt() {
	opkg update &&
		opkg install dnsadblock
	rt=$?
	if [ $rt -eq 0 ]; then
		case $(ask_bool 'Install the GUI?' true) in
		true)
			opkg install luci-app-dnsadblock
			rt=$?
			;;
		esac
	fi
	return $rt
}

upgrade_openwrt() {
	opkg update &&
		opkg upgrade dnsadblock
}

uninstall_openwrt() {
	opkg remove dnsadblock
}

install_ddwrt() {
	if [ "$(nvram get enable_jffs2)" = "0" ]; then
		log_error "JFFS support not enabled"
		log_info "To enabled JFFS:"
		log_info " 1. On the router web page click on Administration."
		log_info " 2. Scroll down until you see JFFS2 Support section."
		log_info " 3. Click Enable JFFS."
		log_info " 4. Click Save."
		log_info " 5. Wait a couple of seconds, then click Apply."
		log_info " 6. Wait again. Go back to the Enable JFFS section, and enable Clean JFFS."
		log_info " 7. Do not click Save. Click Apply instead."
		log_info " 8. Wait untill you get the web-GUI back, then disable Clean JFFS again."
		log_info " 9. Click Save."
		log_info "10. Relaunch this installer."
		exit 1
	fi
	mkdir -p /jffs/dnsadblock &&
		openssl_get https://curl.haxx.se/ca/cacert.pem | http_body >/jffs/dnsadblock/ca.pem &&
		install_bin
}

upgrade_ddwrt() {
	upgrade_bin
}

uninstall_ddwrt() {
	uninstall_bin
	rm -rf /jffs/dnsadblock
}

install_brew() {
	silent_exec brew install dnsadblock/tap/dnsadblock
}

upgrade_brew() {
	silent_exec brew upgrade dnsadblock/tap/dnsadblock
	sudo "$DNSADBLOCK_BIN" install
}

uninstall_brew() {
	silent_exec brew uninstall dnsadblock/tap/dnsadblock
}

install_freebsd() {
	# TODO: port install
	install_bin
}

upgrade_freebsd() {
	# TODO: port upgrade
	upgrade_bin
}

uninstall_freebsd() {
	# TODO: port uninstall
	uninstall_bin
}

install_pfsense() {
	# TODO: port install + UI
	install_bin
}

upgrade_pfsense() {
	# TODO: port upgrade
	upgrade_bin
}

uninstall_pfsense() {
	# TODO: port uninstall
	uninstall_bin
}

install_opnsense() {
	# TODO: port install + UI
	install_bin
}

upgrade_opnsense() {
	# TODO: port upgrade
	upgrade_bin
}

uninstall_opnsense() {
	# TODO: port uninstall
	uninstall_bin
}

ubios_install_source() {
	echo "deb https://api.dnsadblock.com/repo/deb stable main" >/tmp/dnsadblock.list
	podman cp /tmp/dnsadblock.list unifi-os:/etc/apt/sources.list.d/dnsadblock.list
	rm -f /tmp/dnsadblock.list
}

install_ubios() {
	ubios_install_source
	podman exec unifi-os apt-get update
	podman exec unifi-os apt-get install -y dnsadblock
}

upgrade_ubios() {
	ubios_install_source
	podman exec unifi-os apt-get update
	podman exec unifi-os apt-get upgrade -y dnsadblock
}

uninstall_ubios() {
	podman exec unifi-os apt-get remove -y dnsadblock
}

install_type() {
	if [ "$FORCE_INSTALL_TYPE" ]; then
		echo "$FORCE_INSTALL_TYPE"
		return 0
	fi
	case $OS in
	centos | fedora | rhel)
		echo "rpm"
		;;
	debian | ubuntu | elementary | raspbian | linuxmint | pop)
		echo "deb"
		;;
	arch | manjaro)
		#echo "arch" # TODO: fix AUR install
		echo "bin"
		;;
	openwrt)
		# shellcheck disable=SC1091
		. /etc/os-release
		major=$(echo "$VERSION_ID" | cut -d. -f1)
		case $major in
		*[!0-9]*)
			if [ "$VERSION_ID" = "19.07.0-rc1" ]; then
				# No opkg support before 19.07.0-rc2
				echo "bin"
			else
				# Likely 'snapshot' bulid in this case, but still > major version 19
				echo "openwrt"
			fi
			;;
		*)
			if [ "$major" -lt 19 ]; then
				# No opkg support before 19.07.0-rc2
				echo "bin"
			else
				echo "openwrt"
			fi
			;;
		esac
		;;
	asuswrt-merlin)
		echo "merlin"
		;;
	edgeos | synology | clear-linux-os | solus | openbsd | netbsd | overthebox)
		echo "bin"
		;;
	ddwrt)
		echo "ddwrt"
		;;
	darwin)
		if [ -x /usr/local/bin/brew ]; then
			echo "brew"
		else
			log_debug "Homebrew not installed, fallback on binary install"
			echo "bin"
		fi
		;;
	freebsd)
		echo "freebsd"
		;;
	pfsense)
		echo "pfsense"
		;;
	opnsense)
		echo "opnsense"
		;;
	ubios)
		echo "bin"
		;;
	*)
		log_error "Unsupported installation for $(detect_os)"
		return 1
		;;
	esac
}

get_config() {
	"$DNSADBLOCK_BIN" config | grep -E "^$1 " | cut -d' ' -f 2
}

get_config_bool() {
	val=$(get_config "$1")
	case $val in
	true | false)
		echo "$val"
		;;
	esac
	echo "$2"
}

get_config_id() {
	log_debug "Get configuration ID"
	while [ -z "$CONFIG_ID" ]; do
		default=
		prev_id=$(get_config config)
		if [ "$prev_id" ]; then
			prev_id_oneline=$(echo "${prev_id}" | tr '\n' ' ')
			log_debug "Previous config ID: $prev_id_oneline"
			default=" (default=$prev_id_oneline)"
		fi
		print "dnsadblock Configuration ID%s: " "$default"
		read -r id
		if [ -z "$id" ]; then
			id=$prev_id
		fi
		if echo "$id" | grep -qE '^[0-9a-z]{8}$'; then
			CONFIG_ID=$id
			break
		else
			log_error "Invalid connection ID."
			println
			println "ID format is 8 alphanumerical characters."
			println "Your ID can be found on the connections page at:"
			println "	https://dnsadblock.com/app/connections"
			println
		fi
	done
	echo "$CONFIG_ID"
}

log_debug() {
	if [ "$DEBUG" = "1" ]; then
		printf "\033[30;1mDEBUG: %s\033[0m\n" "$*" >&2
	fi
}

log_info() {
	printf "INFO: %s\n" "$*" >&2
}

log_error() {
	printf "\033[31mERROR: %s\033[0m\n" "$*" >&2
}

print() {
	format=$1
	if [ $# -gt 0 ]; then
		shift
	fi
	# shellcheck disable=SC2059
	printf "$format" "$@" >&2
}

println() {
	format=$1
	if [ $# -gt 0 ]; then
		shift
	fi
	# shellcheck disable=SC2059
	printf "$format\n" "$@" >&2
}

doc() {
	# shellcheck disable=SC2059
	printf "\033[30;1m%s\033[0m\n" "$*" >&2
}

menu() {
	while true; do
		n=0
		default=
		for item in "$@"; do
			case $((n % 3)) in
			0)
				key=$item
				if [ -z "$default" ]; then
					default=$key
				fi
				;;
			1)
				echo "$key) $item"
				;;
			esac
			n=$((n + 1))
		done
		print "Choice (default=%s): " "$default"
		read -r choice
		if [ -z "$choice" ]; then
			choice=$default
		fi
		n=0
		for item in "$@"; do
			case $((n % 3)) in
			0)
				key=$item
				;;
			2)
				if [ "$key" = "$choice" ]; then
					if ! "$item"; then
						log_error "$item: exit $?"
					fi
					break 2
				fi
				;;
			esac
			n=$((n + 1))
		done
		echo "Invalid choice"
	done
}

ask_bool() {
	msg=$1
	default=$2
	case $default in
	true)
		msg="$msg [Y|n]: "
		;;
	false)
		msg="$msg [y|N]: "
		;;
	*)
		msg="$msg (y/n): "
		;;
	esac
	while true; do
		print "%s" "$msg"
		read -r answer
		if [ -z "$answer" ]; then
			answer=$default
		fi
		case $answer in
		y | Y | yes | YES | true)
			echo "true"
			return 0
			;;
		n | N | no | NO | false)
			echo "false"
			return 0
			;;
		*)
			echo "Invalid input, use yes or no"
			;;
		esac
	done
}

detect_endiannes() {
	if ! hexdump /dev/null 2>/dev/null; then
		# Some firmware do not contain hexdump, for those, try to detect endiannes
		# differently
		case $(cat /proc/cpuinfo) in
		*BCM5300*)
			# RT-AC66U does not support merlin version over 380.70 which
			# lack hexdump command.
			echo "le"
			;;
		*)
			log_error "Cannot determine endiannes"
			return 1
			;;
		esac
		return 0
	fi
	case $(hexdump -s 5 -n 1 -e '"%x"' /bin/sh | head -c1) in
	1)
		echo "le"
		;;
	2)
		echo ""
		;;
	esac
}

detect_goarch() {
	if [ "$FORCE_GOARCH" ]; then
		echo "$FORCE_GOARCH"
		return 0
	fi
	case $(uname -m) in
	x86_64 | amd64)
		echo "amd64"
		;;
	i386 | i686)
		echo "386"
		;;
	arm)
		# Freebsd does not include arm version
		case "$(sysctl -b hw.model 2>/dev/null)" in
		*A9*)
			echo "armv7"
			;;
		*)
			# Unknown version, fallback to the lowest
			echo "armv5"
			;;
		esac
		;;
	armv5*)
		echo "armv5"
		;;
	armv6* | armv7*)
		if grep -q vfp /proc/cpuinfo 2>/dev/null; then
			echo "armv$(uname -m | sed -e 's/[[:alpha:]]//g')"
		else
			# Soft floating point
			echo "armv5"
		fi
		;;
	aarch64)
		case "$(uname -o 2>/dev/null)" in
		ASUSWRT-Merlin*)
			# XXX when using arm64 build on ASUS AC66U and ACG86U, we get Go error:
			# "out of memory allocating heap arena metadata".
			echo "armv7"
			;;
		*)
			echo "arm64"
			;;
		esac
		;;
	armv8* | arm64)
		echo "arm64"
		;;
	mips*)
		# TODO: detect hardfloat
		echo "$(uname -m)$(detect_endiannes)_softfloat"
		;;
	*)
		log_error "Unsupported GOARCH: $(uname -m)"
		return 1
		;;
	esac
}

detect_goos() {
	if [ "$FORCE_GOOS" ]; then
		echo "$FORCE_GOOS"
		return 0
	fi
	case $(uname -s) in
	Linux)
		echo "linux"
		;;
	Darwin)
		echo "darwin"
		;;
	FreeBSD)
		echo "freebsd"
		;;
	NetBSD)
		echo "netbsd"
		;;
	*)
		log_error "Unsupported GOOS: $(uname -s)"
		return 1
		;;
	esac
}

detect_os() {
	if [ "$FORCE_OS" ]; then
		echo "$FORCE_OS"
		return 0
	fi
	case $(uname -s) in
	Linux)
		case $(uname -o) in
		GNU/Linux)
			if grep -q -e '^EdgeRouter' -e '^UniFiSecurityGateway' /etc/version 2>/dev/null; then
				echo "edgeos"
				return 0
			fi
			if uname -u 2>/dev/null | grep -q '^synology'; then
				echo "synology"
				return 0
			fi
			# shellcheck disable=SC1091
			dist=$(
				. /etc/os-release
				echo "$ID"
			)
			case $dist in
			ubios)
                if [ -z "$(command -v podman)" ]; then
                    log_error "This version of UnifiOS is not supported. Make sure you run version 1.7.0 or above."
                    return 1
                fi
                echo "$dist"; return 0
                ;;
            debian|ubuntu|elementary|raspbian|centos|fedora|rhel|arch|manjaro|openwrt|clear-linux-os|linuxmint|opensuse-tumbleweed|opensuse|solus|pop|neon|overthebox)
				echo "$dist"
				return 0
				;;
			esac
			;;
		ASUSWRT-Merlin*)
			echo "asuswrt-merlin"
			return 0
			;;
		DD-WRT)
			echo "ddwrt"
			return 0
			;;
		esac
		;;
	Darwin)
		echo "darwin"
		return 0
		;;
	FreeBSD)
		if [ -f /etc/platform ]; then
			case $(cat /etc/platform) in
			pfSense)
				echo "pfsense"
				return 0
				;;
			esac
		fi
		if [ -x /usr/local/sbin/opnsense-version ]; then
			case $(/usr/local/sbin/opnsense-version -N) in
			OPNsense)
				echo "opnsense"
				return 0
				;;
			esac
		fi
		echo "freebsd"
		return 0
		;;
	NetBSD)
		echo "netbsd"
		return 0
		;;
	*) ;;
	esac
	log_error "Unsupported OS: $(uname -s)"
	return 1
}

guess_host_type() {
	case $OS in
	pfsense | opnsense | openwrt | asuswrt-merlin | edgeos | ddwrt | synology | overthebox | ubios)
		echo "router"
		;;
	darwin)
		echo "workstation"
		;;
	*)
		echo "unsure"
		;;
	esac
}

asroot() {
	# Some platform (merlin) do not have the "id" command and $USER report a non root username with uid 0.
	if [ "$(grep '^Uid:' /proc/$$/status 2>/dev/null | cut -f2)" = "0" ] || [ "$USER" = "root" ] || [ "$(id -u 2>/dev/null)" = "0" ]; then
		"$@"
	elif [ "$(command -v sudo 2>/dev/null)" ]; then
		sudo "$@"
	else
		echo "Root required"
		su -m root -c "$*"
	fi
}

silent_exec() {
	if [ "$DEBUG" = 1 ]; then
		"$@"
	else
		if ! out=$("$@" 2>&1); then
			rt=$?
			println "\033[30;1m%s\033[0m" "$out"
			return $rt
		fi
	fi
}

bin_location() {
	case $OS in
	centos | fedora | rhel | debian | ubuntu | elementary | raspbian | arch | manjaro | clear-linux-os | linuxmint | opensuse-tumbleweed | opensuse | solus | pop)
		echo "/usr/bin/dnsadblock"
		;;
	openwrt | overthebox)
		echo "/usr/sbin/dnsadblock"
		;;
	darwin | synology)
		echo "/usr/local/bin/dnsadblock"
		;;
	asuswrt-merlin | ddwrt)
		echo "/jffs/dnsadblock/dnsadblock"
		;;
	freebsd | pfsense | opnsense | netbsd | openbsd)
		echo "/usr/local/sbin/dnsadblock"
		;;
	edgeos)
		echo "/config/dnsadblock/dnsadblock"
		;;
	ubios)
		echo "/data/dnsadblock"
		;;
	*)
		log_error "Unknown bin location for $OS"
		;;
	esac
}

get_current_release() {
	if [ -x "$DNSADBLOCK_BIN" ]; then
		$DNSADBLOCK_BIN version | cut -d' ' -f 3
	fi
}

get_release() {
	if [ "$dnsadblock_VERSION" ]; then
		echo "$dnsadblock_VERSION"
	else
		curl="curl -A curl -s"
		if [ -z "$(command -v curl 2>/dev/null)" ]; then
			curl="openssl_get"
		fi
		$curl "https://api.github.com/repos/dnsadblock/proxy-release/releases/latest" |
			grep '"tag_name":' |
			esed 's/.*"([^"]+)".*/\1/' |
			sed -e 's/^v//'
	fi
}

esed() {
	if (echo | sed -E '' >/dev/null 2>&1); then
		sed -E "$@"
	else
		sed -r "$@"
	fi
}

http_redirect() {
	while read -r header; do
		case $header in
		Location:*)
			echo "${header#Location: }"
			return
			;;
		esac
		if [ "$header" = "" ]; then
			break
		fi
	done
	cat >/dev/null
	return 1
}

http_body() {
	sed -n '/^\r/,$p' | sed 1d
}

openssl_get() {
	host=${1#https://*} # https://dom.com/path -> dom.com/path
	path=/${host#*/}    # dom.com/path -> /path
	host=${host%$path}  # dom.com/path -> dom.com
	printf "GET %s HTTP/1.0\nHost: %s\nUser-Agent: curl\n\n" "$path" "$host" |
		openssl s_client -quiet -connect "$host:443" 2>/dev/null
}

main
