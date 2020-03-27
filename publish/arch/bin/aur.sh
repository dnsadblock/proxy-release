#!/bin/bash

set -e

CURRENT_PATH=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
PARENT_PATH=$(cd "${CURRENT_PATH}/../"; pwd -P)
REPO="dnsadblock/proxy-release"

main(){
	GIT_TAG=$(get_latest_release)
	GIT_TAG=$(remove_vversion "$GIT_TAG")
	echo "Creating package for v${GIT_TAG}"

	echo "Cloning AUR repo"
	git clone git+ssh://aur@aur.archlinux.org/dnsadblock.git "${PARENT_PATH}/dnsadblock"

	PKGBUILD_TPL=${PKGBUILD_TPL/__PACKAGE_VERSION__/$GIT_TAG}

	rm -f "$PARENT_PATH/dnsadblock/PKGBUILD"
	rm -f "$PARENT_PATH/dnsadblock/.SRCINFO"

	cat >"$PARENT_PATH/dnsadblock/PKGBUILD" <<EOL
# Maintainer: DnsAdBlock <office@dnsadblock.com>
pkgname=dnsadblock
pkgver=${GIT_TAG}
pkgrel=1
pkgdesc='DnsAdBlock DNS to DOH proxy client'
arch=('x86_64')
url='https://github.com/${REPO}'
license=('MIT')
source=("\$url/releases/download/v\${pkgver}/\${pkgname}_\${pkgver}_linux_amd64.tar.gz")
sha256sums=('@checksum@')
install=\$pkgname.install

package() {
	install -Dm755 \$pkgname "\$pkgdir"/usr/bin/\$pkgname
}


EOL

	echo "Building base image"
	docker build -t dnsadblock/arch $PARENT_PATH

	echo "Creating PKGBUILD"
	docker run --rm -it -v "$PARENT_PATH/dnsadblock":/home/non_root/dnsadblock dnsadblock/arch makepkg -g -f -p PKGBUILD

	echo "Generating sha256sums"
	add_sha256sums

	echo "Creating .SRCINFO"
	docker run --rm -it -v "$PARENT_PATH/dnsadblock":/home/non_root/dnsadblock dnsadblock/arch makepkg --printsrcinfo > "$PARENT_PATH/dnsadblock/.SRCINFO"

	cd "${PARENT_PATH}/dnsadblock"

	# do not commit unless we have the required files present
	[ -f "$PARENT_PATH/dnsadblock/.SRCINFO" ] && [ -f "$PARENT_PATH/dnsadblock/PKGBUILD" ] && {
		git commit -am "Release for version: v${GIT_TAG}"
		git push origin master
	}
}

get_latest_release() {
	curl -s \
		-H "Accept: application/json" \
		"https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | cut -d'"' -f4
}

remove_vversion() {
	echo "$1" | cut -c2-9999
}

add_sha256sums(){
	shasum=$(sha256sum "$PARENT_PATH/dnsadblock/dnsadblock_${GIT_TAG}_linux_amd64.tar.gz" | cut -f1 -d' ')
	shasum=$(trim "$shasum")
	echo "sha256sums=('${shasum}')" >> "$PARENT_PATH/dnsadblock/PKGBUILD"
}

trim() {
    local var="$*"
    # remove leading whitespace characters
    var="${var#"${var%%[![:space:]]*}"}"
    # remove trailing whitespace characters
    var="${var%"${var##*[![:space:]]}"}"
    printf '%s' "$var"
}

main