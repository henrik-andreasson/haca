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

result=$(http --verify cacerts.pem "${API_URL}/ca/list" \
    "Authorization:Bearer $token")
#echo $result | jq -c .items[]
mapfile -t cas < <(echo $result | jq -c .items[])

for cert in "${cas[@]}"; do
#  echo $cert
  id=$(echo $cert | jq .id)
  result2=$(http --verify cacerts.pem "${API_URL}/ca/${id}" \
      "Authorization:Bearer $token")
  echo $result2 | jq .
done
