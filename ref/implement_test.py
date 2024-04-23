# Import the functions from implementation script
from implement import (
    generate_keypair_768,
    encrypt_768,
    decrypt_768,
    CRYPTO_PUBLICKEYBYTES_768,
    CRYPTO_SECRETKEYBYTES_768,
    CRYPTO_CIPHERTEXTBYTES_768,
    CRYPTO_BYTES_768
)

def test_keypair_generation():
    public_key, private_key = generate_keypair_768()
    assert len(public_key) == CRYPTO_PUBLICKEYBYTES_768
    assert len(private_key) == CRYPTO_SECRETKEYBYTES_768
    print("Keypair generation test passed!")

def test_encryption_decryption():
    # Generate keypair
    public_key, private_key = generate_keypair_768()
    
    # Encrypt a message using the public key
    ciphertext, shared_secret_enc = encrypt_768(public_key)
    assert len(ciphertext) == CRYPTO_CIPHERTEXTBYTES_768
    assert len(shared_secret_enc) == CRYPTO_BYTES_768
    
    # Decrypt the message using the private key
    shared_secret_dec = decrypt_768(ciphertext, private_key)
    assert shared_secret_enc == shared_secret_dec
    print("Encryption and decryption test passed!")

# Run the tests
test_keypair_generation()
test_encryption_decryption()
