# Device That Publishes the Public key
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import json
from ctypes import CDLL

from implement import (
    generate_keypair_768,
    encrypt_768,
    decrypt_768,
    CRYPTO_PUBLICKEYBYTES_768,
    CRYPTO_SECRETKEYBYTES_768,
    CRYPTO_CIPHERTEXTBYTES_768,
    CRYPTO_BYTES_768
)

# Load the Kyber shared library
kyber = CDLL('./libpqcrystals_kyber768_ref.so')

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT Broker!")
        client.subscribe("encrypted/messages")
        client.subscribe("ciphertext")
    else:
        print("Failed to connect, return code %d\n", rc)

import base64

def on_message(client, userdata, msg):
    if msg.topic == "ciphertext":
        # Base64 decode and decrypt to get the shared secret
        try:
            ciphertext = base64.b64decode(msg.payload)
            shared_secret = decrypt_768(ciphertext, userdata['private_key'])
            print("Decrypted shared secret successfully.")

            # Example of deriving AES key directly from shared secret
            # Adjust this depending on the key size requirements (e.g., 16 bytes for AES-128)
            userdata['aes_key'] = shared_secret[:16]
            print("AES key set successfully.")
        except Exception as e:
            print(f"Failed during decryption of shared secret or setting AES key: {str(e)}")
            return

    elif msg.topic == "encrypted/messages":
        # Check if AES key is available before attempting decryption
        if 'aes_key' not in userdata:
            print("AES key is not available for decryption.")
            return

        # Extract nonce, ciphertext, and tag from the payload
        nonce = msg.payload[:16]
        tag = msg.payload[-16:]
        ciphertext = msg.payload[16:-16]

        # Decrypt the message using AES key
        plaintext = aes_decrypt(nonce, ciphertext, tag, userdata['aes_key'])
        if plaintext:
            print("Decrypted message:", plaintext.decode('utf-8'))
        else:
            print("Decryption failed or data tampered with.")


def aes_decrypt(nonce, ciphertext, tag, key):
    # Initialize AES cipher in GCM mode with the received nonce
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        print(f"Decryption failed: {str(e)}")
        return None
    except Exception as e:
        print(f"Unexpected error during decryption: {str(e)}")
        return None  

def connect_to_mqtt(broker_address, port, keepalive, client_id, userdata):
    client = mqtt.Client(client_id, userdata=userdata)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(broker_address, port, keepalive)
    client.loop_start()
    return client

def run_publisher():
    broker = "localhost"
    port = 1883
    keepalive = 60
    client_id = "kyber-mqtt-publisher"
    device_id = 1234
    
    # Generate the public and private keys
    public_key, private_key = generate_keypair_768()

    userdata = {
        'device_id': device_id,
        'private_key': private_key  # Store private key in userdata for decryption
    }
    
    client = connect_to_mqtt(broker, port, keepalive, client_id, userdata)
    publish_key(client, device_id, public_key)
    
    client.loop_forever()

def publish_key(client, device_id, public_key):
    topic = f"public_keys/{device_id}"
    result = client.publish(topic, public_key.hex())  # Publish the key as a hex string
    if result[0] == 0:
        print(f"Public key sent to topic `{topic}`")
    else:
        print("Failed to send public key")


if __name__ == "__main__":
    run_publisher()
