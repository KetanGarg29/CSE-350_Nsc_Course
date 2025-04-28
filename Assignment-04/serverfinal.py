import hashlib
import json
import time
import requests
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import ntplib
from datetime import datetime

app = Flask(__name__)

with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

def get_gmt_time():
    try:
        client = ntplib.NTPClient()
        response = client.request('pool.ntp.org', version=3)
        utc_time = datetime.utcfromtimestamp(response.tx_time).isoformat()
        return utc_time
    except Exception as e:
        print(f"Failed to fetch GMT time via NTP: {e}")
        return None

def set_gmt_time():
    try:
        client = ntplib.NTPClient()
        response = client.request('pool.ntp.org', version=3)
        return
    except Exception as e:
        print(f"Failed to set the GMT time via NTP: {e}")
        return

@app.route('/timestamp', methods=['POST'])
def timestamp():
    data = request.get_json()
    result = process_encrypted_hash(data)
    if isinstance(result, tuple):  # error tuple (response, status)
        return result

    document_hash = result
    return generate_timestamp_response(document_hash)


def process_encrypted_hash(data):
    encrypted_hash_hex = data.get('encrypted_hash')
    if not encrypted_hash_hex:
        return jsonify({"error": "encrypted_hash missing"}), 400

    try:
        encrypted_hash_bytes = bytes.fromhex(encrypted_hash_hex)
        document_hash = private_key.decrypt(
            encrypted_hash_bytes,
            padding.PKCS1v15()
        ).decode()
        return document_hash
    except Exception as e:
        set_gmt_time()
        return jsonify({"error": f"Decryption failed: {e}"}), 400


def generate_timestamp_response(document_hash):
    gmt_time = get_gmt_time()
    if gmt_time is None:
        return jsonify({"error": "Failed to fetch GMT time"}), 500

    payload = {
        "document_hash": document_hash,
        "gmt_time": gmt_time
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    set_gmt_time()
    signature = private_key.sign(
        payload_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return jsonify({
        "document_hash": document_hash,
        "gmt_time": gmt_time,
        "signature": signature.hex()
    })

if __name__ == '__main__':
    app.run(port=5000)