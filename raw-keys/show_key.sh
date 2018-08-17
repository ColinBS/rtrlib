#!/bin/bash

if [[ $1 = *".cert"* ]]; then
    openssl x509 -in $1 -inform DER -text -noout
elif [[ $1 = *".der"* ]]; then
    openssl pkey -in $1 -inform DER -text -noout
fi
