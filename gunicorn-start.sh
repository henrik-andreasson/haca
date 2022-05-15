#!/bin/bash

if [ "x${INSTALL_PATH}" == "x" ] ; then

	if [ -d "/haca" ] ; then
		INSTALL_PATH=/haca
	elif [ -d "/opt/haca" ] ; then
		INSTALL_PATH=/opt/haca
	fi
fi

cd "${INSTALL_PATH}"

if [ "x${USE_CERT}" == "x" ] ; then
	USE_CERT=0
fi

if [ "x$CERT" != "x" ] ; then
  echo "$CERT" | tr ';' '\n' > "${INSTALL_PATH}/cert.pem"
  let USE_CERT="$USE_CERT + 1"
fi

if [ "x$CA" != "x" ] ; then
  echo "$CA" | tr ';' '\n' > "${INSTALL_PATH}/ca.pem"
  let USE_CERT="$USE_CERT + 1"
fi

if [ "x$KEY" != "x" ] ; then
  echo "$KEY" | tr ';' '\n' > "${INSTALL_PATH}/key.pem"
  let USE_CERT="$USE_CERT + 1"
fi

if [ "x${PORT}" != "x" ] ; then
  LISTEN="${PORT}"
else
  LISTEN=5000
fi

EXTRA_OPTIONS=""
if [ "x$OPTIONS" != "x" ] ; then
  EXTRA_OPTIONS="$OPTIONS"
else
  EXTRA_OPTIONS=""
fi

GUNICORN=""
if [ -f "/usr/bin/gunicorn3" ] ; then
	GUNICORN="/usr/bin/gunicorn3"
elif [ -f "/usr/bin/gunicorn" ] ; then
	GUNICORN="/usr/bin/gunicorn"
else
	echo "no gunicorn found"
	exit -1
fi

echo "USE CERT: $USE_CERT"
if [ $USE_CERT -ge 1 ] ; then
		echo "SSL... "
    $GUNICORN haca:app -b 0.0.0.0:${LISTEN} \
         --pid "${INSTALL_PATH}/teamplan.pid" \
         --keyfile "${INSTALL_PATH}/key.pem"  \
         --certfile  "${INSTALL_PATH}/cert.pem" \
				 --ca-certs "${INSTALL_PATH}/ca.pem" ${EXTRA_OPTIONS}

else

    $GUNICORN haca:app -b 0.0.0.0:${LISTEN} ${EXTRA_OPTIONS}

fi
