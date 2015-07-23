#!/bin/sh
openssl genrsa 2048 > secrets/pki/mykey.pem
openssl req -new -x509 -key secrets/pki/mykey.pem -out secrets/pki/mycert.pem -days 365

