#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "kem.h"
#include "params.h"
#include "randombytes.h"

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
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

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
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

int main() {
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
    uint8_t private_key[CRYPTO_SECRETKEYBYTES];
    uint8_t ciphertext[CRYPTO_CIPHERTEXTBYTES];
    uint8_t shared_secret_enc[CRYPTO_BYTES], shared_secret_dec[CRYPTO_BYTES];
    unsigned char *iv = (unsigned char *)"0123456789012345"; // IV for AES encryption

    // Message to be encrypted
    unsigned char message[] = "Hello, World!";
    unsigned char encrypted_message[128]; // Ensure this buffer is large enough
    unsigned char decrypted_message[128]; // Ensure this buffer is large enough

    // Generate Kyber key pair
    crypto_kem_keypair(public_key, private_key);

    // Encapsulate a secret using the public key
    crypto_kem_enc(ciphertext, shared_secret_enc, public_key);

    // Decapsulate the secret using the private key
    crypto_kem_dec(shared_secret_dec, ciphertext, private_key);

    // Encrypt the message using the shared secret as the key
    int encrypted_message_len = encrypt(message, strlen((char *)message), shared_secret_enc, iv, encrypted_message);

    printf("Encrypted Message: ");
    for (int i = 0; i < encrypted_message_len; i++) {
        printf("%02x", encrypted_message[i]);
    }
    printf("\n");

    // Decrypt the message using the shared secret as the key
    int decrypted_message_len = decrypt(encrypted_message, encrypted_message_len, shared_secret_dec, iv, decrypted_message);
    decrypted_message[decrypted_message_len] = '\0'; // Null-terminate the decrypted message

    printf("Decrypted Message: %s\n", decrypted_message);

    return 0;
}
