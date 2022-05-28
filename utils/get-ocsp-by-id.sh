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

result=$(http --verify cacerts.pem "${API_URL}/ocsp/list" \
    "Authorization:Bearer $token")
#echo $result | jq -c .items[]
mapfile -t ocsps < <(echo $result | jq -c .items[])

for ocsp in "${ocsps[@]}"; do
#  echo $cert
  id=$(echo $ocsp | jq .id)
  result2=$(http --verify cacerts.pem "${API_URL}/ocsp/${id}" \
      "Authorization:Bearer $token")
  echo $result2 | jq .
done
