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
  result=$(http --verify cacerts.pem  POST "${API_URL}/cert/generate" \
    "name=${name}" \
    "userid=${userid}" \
    "serial=${serial}" \
    "orgunit=${orgunit}" \
    "org=${org}" \
    "country=${country}" \
    "profile=${profile}" \
    "sandns=${sandns}" \
    "service_name=${service_name}" \
    "ca_name=${ca_name}" \
    "status=${status}" \
    "validity_start=${validity_start}" \
    "validity_end=${validity_end}" \
    "Authorization:Bearer $token")

    echo $result | jq .
    result_cert=$(echo $result | jq .pemcert | tr -d \" )
    result_key=$(echo $result | jq .pemkey | tr -d \"   )
    result_ca=$(echo $result | jq .pemcacert | tr -d \" )
    echo ${result}      > "${name}.log"
    echo "${result_cert@E}" > "${name}.crt"
    echo "${result_key@E}"  > "${name}.key"
    echo "${result_ca@E}"  > "${name}.ca"
done
