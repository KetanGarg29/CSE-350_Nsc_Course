import hashlib
import json
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def hashify(file_path):
    with open(file_path, "rb") as f:
        document = f.read()
    return hashlib.sha256(document).hexdigest()

def e_d_h(document_hash):
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    encrypted = public_key.encrypt(
        document_hash.encode(),
        padding.PKCS1v15()
    )
    return encrypted.hex()

def aks_timestamp(encrypted_hash):
    response = requests.post(
        "http://localhost:5000/timestamp",
        json={"encrypted_hash": encrypted_hash}
    )
    return response.json()

def main():
    document_path = input("Enter path to your document: ").strip()
    document_hash = hashify(document_path)
    print(f"Document SHA256 hash: {document_hash}")

    encrypted_hash = e_d_h(document_hash)
    timestamp_certificate = aks_timestamp(encrypted_hash)

    with open(document_path + ".timestamp", "w") as f:
        json.dump(timestamp_certificate, f, indent=4)

    print("Timestamp certificate saved.")

if __name__ == "__main__":
    main()