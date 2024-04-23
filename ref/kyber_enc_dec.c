#include "kem.h"
#include "params.h"
#include "rng.h"
#include "symmetric.h"
#include "verify.h"
#include "indcpa.h"
#include "api.h"

// Function to generate a public and private key pair
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    size_t i;
    indcpa_keypair(pk, sk);
    for(i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++)
        sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
    hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    randombytes(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);
    return 0;
}

// Function to encapsulate a shared secret using a public key
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];
    
    randombytes(buf, KYBER_SYMBYTES);
    hash_h(buf, buf, KYBER_SYMBYTES);
    hash_h(buf + KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);
    indcpa_enc(ct, buf, pk, kr + KYBER_SYMBYTES);
    hash_h(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
    kdf(ss, kr, 2 * KYBER_SYMBYTES);
    return 0;
}

// Function to decapsulate a shared secret using a ciphertext and a private key
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    size_t i;
    int fail;
    uint8_t buf[2 * KYBER_SYMBYTES];
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES];
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;
    
    indcpa_dec(buf, ct, sk);
    for(i = 0; i < KYBER_SYMBYTES; i++)
        buf[KYBER_SYMBYTES + i] = sk[KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES + i];
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);
    indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);
    fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);
    hash_h(kr + KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
    cmov(kr, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES, fail);
    kdf(ss, kr, 2 * KYBER_SYMBYTES);
    return 0;
}

