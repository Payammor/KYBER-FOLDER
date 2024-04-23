import paho.mqtt.client as mqtt
from ctypes import CDLL, POINTER, c_ubyte, c_int, create_string_buffer

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

# MQTT Callbacks
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT Broker!")
        # Subscribe to the public key topic after connecting
        client.subscribe(userdata['public_key_topic'])
        print(f"Subscribed to {userdata['public_key_topic']}")
    else:
        print("Failed to connect, return code %d\n", rc)

def on_message(client, userdata, msg):
    if msg.topic == userdata['public_key_topic']:
        public_key = msg.payload.decode()
        print(f"Received Public Key: {public_key}")
        # Update the status that public key is received
        publish_status(client, userdata['status_topic'], "Public key received")
        userdata['received_key'] = public_key  # Store the public key if needed further

def publish_status(client, topic, message):
    result = client.publish(topic, message)
    if result[0] == 0:
        print(f"Status `{message}` sent to topic `{topic}`")
    else:
        print("Failed to send status message")

# MQTT Connection
def connect_to_mqtt(broker_address, port, keepalive, client_id, public_key_topic, status_topic):
    client = mqtt.Client(client_id, userdata={
        'public_key_topic': public_key_topic,
        'status_topic': status_topic,
        'received_key': None
    })
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(broker_address, port, keepalive)
    client.loop_start()
    return client

# Main Execution Logic
def run_subscriber():
    broker = "localhost"  # MQTT Broker address
    port = 1883  # MQTT port, typically 1883 for non-TLS connections
    keepalive = 60  # Keepalive interval in seconds
    client_id = "kyber-mqtt-subscriber"

    # Get device ID from user input
    device_id = input("Enter device ID to subscribe for its public key: ")

    # Define topics
    public_key_topic = f"public_keys/{device_id}"
    status_topic = f"public_keys/{device_id}/key_status"

    # Connect to the broker
    client = connect_to_mqtt(broker, port, keepalive, client_id, public_key_topic, status_topic)

    # Allow the client to process incoming and outgoing messages
    try:
        input("Press Enter to exit...\n")
    finally:
        client.loop_stop()  # Stop the network loop

if __name__ == "__main__":
    run_subscriber()
