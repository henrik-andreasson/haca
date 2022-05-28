# command line interface

Use the tools

    cd utils

# CA Operations

Create a CA with values from csv file

    ./create-ca.sh test-input-create-ca.csv

List all CA:s

    ./list-ca.sh

Get all info by a ID

    ./get-ca-by-id.sh

Get all info by Name

    ./get-ca-by-name.sh


# Cert Operations

Create cert via values in a csv file

    ./create-cert-and-keys.sh test-input-create-cert.csv

List all certs

    ./list-cert.sh

Get info on a cert via it's ID

    ./get-cert-by-id.sh

Get info on a cert via it's Name

    ./get-cert-by-name.sh testcert49

# CRL Operations

Create CRL for a CA

    ./create-crl.sh test3-api-ca

Get the CRL for a CA

    ./get-crl-by-name.sh test2-api-ca

List CRLs

    ./list-crl.sh

Get a CRL via ID

    ./get-crl-by-id.sh 2

# OCSP Operations

Create a OCSP Responder via values in a csv

    ./create-ocsp.sh test-input-create-ocsp.csv

List all OCSP Responders

    ./list-ocsp.sh

Get info about a OCSP Responder via it's Name

    ./get-ocsp-by-name.sh

Get info about a OCSP Responder via it's ID

    ./get-ocsp-by-id.sh
