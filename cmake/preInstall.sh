#!/bin/sh
DST=${RPM_INSTALL_PREFIX}
mkdir -p ${DST}/plug/protocol/
touch ${DST}/plug/conflist.inf
touch ${DST}/etc/entrylist.conf
if [[ -z `grep -rn 'http.inf' ${DST}/plug/conflist.inf` ]];then
	sed -i '/\[protocol\]/a\./plug/protocol/http/http.inf' ${DST}/plug/conflist.inf
fi
if [[ -z `grep -rn 'HTTP' ${DST}etc/entrylist.conf` ]];then
	echo "HTTP" >>  ${DST}/etc/entrylist.conf
fi
