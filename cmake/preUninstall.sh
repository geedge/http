#!/bin/sh
if [ $1 == 0 ]; then
	DST=${RPM_INSTALL_PREFIX}

	mkdir -p ${DST}/plug/protocol/
	touch ${DST}/plug/conflist.inf

	sed -i '/http.inf/d' ${DST}/plug/conflist.inf
	sed -i '/HTTP/d' ${DST}/etc/entrylist.conf
fi
