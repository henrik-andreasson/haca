
# REST API

to use the REST API there is new login step, get a jwt token first using httpie

```
http --verify cacerts.pem --auth "$username:$password" POST "${apiserverurl}/tokens" | jq ".token" | sed 's/\"//g'
```

then you can create a new service:

```
http --verify cacerts.pem --verbose POST "${API_URL}/service" \
  "name=${name}" \
  "color=${color}" \
  "Authorization:Bearer $token"
```

to help with getting started with the REST API there are scripts for all API:s in utils/
