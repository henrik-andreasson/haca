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
    ca_name=$1
else
    echo "ca_name must be arg1"
    exit
fi

result=$(http --verify cacerts.pem "${API_URL}/crl/${ca_name}" \
    "Authorization:Bearer $token")
echo $result
result_crl=$(echo $result | jq .crl | tr -d \" )
echo ${result}      > "${ca_name}.log"
echo "${result_crl@E}" > "${ca_name}.crl"
