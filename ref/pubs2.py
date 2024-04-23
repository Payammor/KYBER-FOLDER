# Device That Recieves the Public Key
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import base64
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

# Function to derive AES key from shared secret
def derive_aes_key(shared_secret, key_length_bits=256):
    key_length_bytes = key_length_bits // 8
    return hashlib.sha256(shared_secret).digest()[:key_length_bytes]

# Function to encrypt data using AES in GCM mode
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag

# Function to handle received public key and encrypt a shared secret
def ciphertext_shared_secret(userdata, client, public_key):
    ciphertext, shared_secret = encrypt_768(public_key)
    userdata['shared_secret'] = shared_secret
    aes_key = derive_aes_key(shared_secret)
    base64_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    client.publish("ciphertext", base64_ciphertext)
    print("Published Ciphertext to 'ciphertext'.")
    return aes_key

# MQTT Callbacks
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT Broker!")
        client.subscribe(userdata['public_key_topic'])
        print(f"Subscribed to {userdata['public_key_topic']}")
    else:
        print("Failed to connect, return code %d\n", rc)

def on_message(client, userdata, msg):
    if msg.topic == userdata['public_key_topic']:
        public_key_hex = msg.payload.decode()
        public_key = bytes.fromhex(public_key_hex)  # Convert hex to bytes if necessary
        print(f"Received Public Key.")
        userdata['received_key'] = public_key  # Store the public key if needed further
        aes_key = ciphertext_shared_secret(userdata, client, public_key)
        # Example message to send
        send_encrypted_message(client, "encrypted/messages", "Hello Secure World!", aes_key)

# Function to send encrypted message
def send_encrypted_message(mqtt_client, topic, plaintext, aes_key):
    nonce, ciphertext, tag = aes_encrypt(plaintext.encode('utf-8'), aes_key)
    payload = base64.b64encode(nonce + ciphertext + tag).decode('utf-8')
    mqtt_client.publish(topic, payload)

# Setup and run the MQTT client
def connect_to_mqtt(broker_address, port, keepalive, client_id, public_key_topic):
    client = mqtt.Client(client_id, userdata={'public_key_topic': public_key_topic})
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(broker_address, port, keepalive)
    return client

def run_subscriber():
    broker = "localhost"
    port = 1883
    keepalive = 60
    client_id = "kyber-mqtt-subscriber"
    device_id = 1234
    public_key_topic = f"public_keys/{device_id}"
    client = connect_to_mqtt(broker, port, keepalive, client_id, public_key_topic)
    client.loop_forever()

if __name__ == "__main__":
    run_subscriber()
