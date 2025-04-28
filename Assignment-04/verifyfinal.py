import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

def verify(document_path, certificate_path, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    with open(document_path, "rb") as f:
        document = f.read()
    document_hash = hashlib.sha256(document).hexdigest()

    with open(certificate_path, "r") as f:
        certificate = json.load(f)

    if document_hash != certificate["document_hash"]:
        print("Verification failed! Certificate/Document is changed or tampered.")
        return False

    payload = {
        "document_hash": certificate["document_hash"],
        "gmt_time": certificate["gmt_time"]
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    signature = bytes.fromhex(certificate["signature"])

    try:
        public_key.verify(
            signature,
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f"Verification successful. Document existed at {certificate['gmt_time']} UTC.")
        return True
    except Exception as e:
        print("Verification failed! Certificate/Document is changed or tampered.")
        return False

def main():
    doc = input("Enter document path: ").strip()
    cert = input("Enter timestamp certificate path: ").strip()
    pub = input("Enter public key path: ").strip()
    verify(doc, cert, pub)

if __name__ == "__main__":
    main()
