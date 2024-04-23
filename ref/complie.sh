#!/bin/bash

# Set compiler flags
CC=gcc
CFLAGS="-Wall -Wextra -O3 -fPIC"
LDFLAGS="-shared"

# Set source files directory
SRC_DIR="/home/gp2/kyber/ref"

# Set source files
ENC_SRC="$SRC_DIR/encryption.c"
KYBER_LIB="$SRC_DIR/libpqcrystals_kyber$ALG_ref.so"
AES_LIB="$SRC_DIR/libpqcrystals_aes256ctr_ref.so"
FIPS_LIB="$SRC_DIR/libpqcrystals_fips202_ref.so"

# Set output directory
OUT_DIR="$SRC_DIR"

# Set output shared library name
OUT_LIB="libencryption.so"

# Compile encryption.c with Kyber and symmetric crypto libraries
$CC $CFLAGS -o $OUT_DIR/$OUT_LIB -I$SRC_DIR $ENC_SRC $KYBER_LIB $AES_LIB $FIPS_LIB $LDFLAGS -lcrypto -lssl
