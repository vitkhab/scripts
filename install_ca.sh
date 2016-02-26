#!/bin/bash
# Maintainer: Vitaly Khabarov <vitkhab@gmail.com>
# Description: This script installs CA certificate into openssl
# Tested: DER and PEM formats on Debian
# Usage: ./install_ca.sh /path/to/ca.cer

CAPATH="$1"
CAFILE=`basename "$CAPATH"`
CAEXT="${CAFILE##*.}"
CANAME="${CAFILE%.*}"
OPENSSLDIR=`openssl version -d | cut -d'"' -f2`


# Find out input format
openssl x509 -noout -fingerprint -in $CAPATH -inform pem &> /dev/null
if [[ $? -eq 0 ]]; then FORMAT=pem; fi
openssl x509 -noout -fingerprint -in $CAPATH -inform der &> /dev/null
if [[ $? -eq 0 ]]; then FORMAT=der; fi

# Convert certificate to PEM-format
case $FORMAT in
pem)
    cp $CAPATH $OPENSSLDIR/$CANAME.pem
    ;;
der)
    openssl x509 -in $CAPATH -inform der -outform pem -out $OPENSSLDIR/$CANAME.pem
    ;;
*)
    echo "Unknown format"
    exit 0
    ;;
esac

# Create symbolic link for OpenSSL
ln -s $OPENSSLDIR/$CANAME.pem $OPENSSLDIR/`openssl x509 -hash -noout -in $OPENSSLDIR/$CANAME.pem`.0

