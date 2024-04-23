#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "kem.h"
#include "params.h"
#include "randombytes.h"
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *key,
                const uint8_t *iv, uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *key,
                const uint8_t *iv, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// Kyber wrapper functions

void kyber_keypair(uint8_t *public_key, uint8_t *private_key) {
    crypto_kem_keypair(public_key, private_key);
}

int kyber_encapsulate(const uint8_t *public_key, uint8_t *ciphertext, uint8_t *shared_secret) {
    return crypto_kem_enc(ciphertext, shared_secret, public_key);
}

int kyber_decapsulate(const uint8_t *ciphertext, const uint8_t *private_key, uint8_t *shared_secret) {
    return crypto_kem_dec(shared_secret, ciphertext, private_key);
}

// Expose simple encrypt and decrypt wrapper functions compatible with Python ctypes

int encrypt(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *key,
            const uint8_t *iv, uint8_t *ciphertext) {
    return aes_encrypt(plaintext, plaintext_len, key, iv, ciphertext);
}

int decrypt(const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *key,
            const uint8_t *iv, uint8_t *plaintext) {
    return aes_decrypt(ciphertext, ciphertext_len, key, iv, plaintext);
}
