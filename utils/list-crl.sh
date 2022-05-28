#!/bin/bash

if [ -f variables ] ; then
  . variables
  echo "URL: ${API_URL}"   >&2
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

result=$(http --verify cacerts.pem "${API_URL}/crl/list" \
    "Authorization:Bearer $token")
echo $result | jq .
