#!/bin/bash

if [ -f variables ] ; then
  . variables
  echo "URL: ${API_URL}" >&2
  echo "User: ${API_USER}" >&2

fi

token=""
if [ -f rest-get-token.sh ] ; then
  . rest-get-token.sh
  token=$(get_new_token)
  if [ $? -ne 0 ] ; then
    echo "failed to get a login token"
    exit
  fi
else
  echo "login/get token failed"
  exit
fi


if [ "x$1" != "x" ] ; then
    csvfile=$1
else
    echo "arg1 must be a file with cert definitions in it"
    echo "name,userid,serial,orgunit,org,country,profile,sandns,service_name,ca_name"
    exit
fi

IFS=$'\n'
CERTRAND="ha$RANDOM"
for row in $(cat "${csvfile}") ; do

  name=$(echo $row | cut -f1 -d\,)
  userid=$(echo $row | cut -f2 -d\,)
  serial=$(echo $row | cut -f3 -d\,)
  orgunit=$(echo $row | cut -f4 -d\,)
  org=$(echo $row     | cut -f5 -d\,)
  country=$(echo $row | cut -f6 -d\,)
  profile=$(echo $row | cut -f7 -d\,)
  sandns=$(echo $row | cut -f8 -d\,)
  service_name=$(echo $row | cut -f9 -d\,)
  ca_name=$(echo $row | cut -f10 -d\,)
  status=$(echo $row | cut -f11 -d\,)
  validity_start=$(echo $row | cut -f12 -d\,)
  validity_end=$(echo $row | cut -f13 -d\,)

  iscomment=$(echo $row | grep "^#" )
  if [ "x$iscomment" != "x" ] ; then
    continue
  fi

  i=0
  while [ $i -lt 100 ] ; do
    http --verify cacerts.pem --verbose POST "${API_URL}/cert/generate" \
      "name=${name}${CERTRAND}${i}" \
      "userid=${userid}${CERTRAND}${i}" \
      "serial=${serial}${CERTRAND}${i}" \
      "orgunit=${orgunit}${CERTRAND}${i}" \
      "org=${org}${CERTRAND}${i}" \
      "country=${country}" \
      "profile=${profile}" \
      "sandns=${sandns}" \
      "service_name=${service_name}" \
      "ca_name=${ca_name}" \
      "status=${status}" \
      "validity_start=${validity_start}" \
      "validity_end=${validity_end}" \
      "Authorization:Bearer $token"

      let i++
    done

done
