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
        # Subscribe to the status topic to receive confirmation messages
        status_topic = f"public_keys/{userdata['device_id']}/key_status"
        client.subscribe(status_topic)
        print(f"Subscribed to status topic: {status_topic}")
    else:
        print("Failed to connect, return code %d\n", rc)

def on_message(client, userdata, msg):
    print(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")

# MQTT Connection
def connect_to_mqtt(broker_address, port, keepalive, client_id, device_id):
    client = mqtt.Client(client_id, userdata={'device_id': device_id})
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(broker_address, port, keepalive)
    client.loop_start()
    return client

# MQTT Publish
def publish_key(client, device_id, public_key):
    topic = f"public_keys/{device_id}"
    result = client.publish(topic, public_key.hex())  # Publish the key as a hex string
    if result[0] == 0:
        print(f"Public key sent to topic `{topic}`")
    else:
        print("Failed to send public key")

# Main Execution Logic
def run_publisher():
    broker = "localhost"  # MQTT Broker address
    port = 1883  # MQTT port, typically 1883 for non-TLS connections
    keepalive = 60  # Keepalive interval in seconds
    client_id = "kyber-mqtt-publisher"

    # Get device ID from user input
    device_id = input("Enter device ID: ")

    # Generate the public and private keys
    public_key, _ = generate_keypair_768()

    # Connect to the broker with device_id passed as userdata
    client = connect_to_mqtt(broker, port, keepalive, client_id, device_id)

    # Publish the public key to the MQTT topic
    publish_key(client, device_id, public_key)

    # Allow the client to process incoming and outgoing messages
    try:
        input("Press Enter to exit...\n")
    finally:
        client.loop_stop()  # Stop the network loop

if __name__ == "__main__":
    run_publisher()
