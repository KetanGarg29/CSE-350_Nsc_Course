import datetime
import random

ID_A = "Client_A"
ID_B = "Client_B"
ID_CA = "CertAuth"
DURATION = 3600  
MOD_N = 100003 

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return (g, x, y)
def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m


e_fixed = 65537 
d_fixed_A = modinv(e_fixed, MOD_N - 1) 

e_fixed_B = 65539  
d_fixed_B = modinv(e_fixed_B, MOD_N - 1)  
d_ca = 5  
e_ca = modinv(d_ca, MOD_N - 1)
print("CA Public Exponent (e_ca):", e_ca)

e_A, d_A = e_fixed, d_fixed_A
e_B, d_B = e_fixed_B, d_fixed_B
print("\nGenerated Keys for Clients:")
print("Client A Public Key:", e_A)
print("Client B Public Key:", e_B)

CA_DATABASE = {
    ID_A: e_A,
    ID_B: e_B
}

def sign_certificate(client_id, public_key):
    timestamp = datetime.datetime.now().isoformat()
    cert_data = f"{client_id},{public_key},{timestamp},{DURATION},{ID_CA}"
    print(f"\n[CA] Certificate Data for {client_id}:", cert_data)
    m_int = sum(bytearray(cert_data, 'utf-8')) % MOD_N  
    signature = pow(m_int, d_ca, MOD_N)  
    print(f"[CA] Signature for {client_id}:", signature)
    return (cert_data, signature)

def request_certificate(client_id):
    print(f"\n[Request] {client_id} is requesting certificate.")
    if client_id == ID_A:
        return sign_certificate(ID_A, e_A)
    elif client_id == ID_B:
        return sign_certificate(ID_B, e_B)
    else:
        print("[Request] Client not found in CA database.")
        return None, None

cert_A_data, cert_A_signature = request_certificate(ID_A)
cert_B_data, cert_B_signature = request_certificate(ID_B)

if cert_A_data and cert_B_data:
    cert_A_m_int = sum(bytearray(cert_A_data, 'utf-8')) % MOD_N
    recovered_A = pow(cert_A_signature, e_ca, MOD_N)
    verified_A = (recovered_A == cert_A_m_int)
    print("\n[Verification] Certificate for Client A:")
    print("Recovered from signature:", recovered_A)
    print("Verification result for Client A:", verified_A)

    cert_B_m_int = sum(bytearray(cert_B_data, 'utf-8')) % MOD_N
    recovered_B = pow(cert_B_signature, e_ca, MOD_N)
    verified_B = (recovered_B == cert_B_m_int)
    print("\n[Verification] Certificate for Client B:")
    print("Recovered from signature:", recovered_B)
    print("Verification result for Client B:", verified_B)

    if verified_A and verified_B:
        cert_A_fields = cert_A_data.split(',')
        public_key_A_extracted = int(cert_A_fields[1])
        print("\n[Extraction] Extracted Client A Public Key:", public_key_A_extracted)
        
        cert_B_fields = cert_B_data.split(',')
        public_key_B_extracted = int(cert_B_fields[1])
        print("[Extraction] Extracted Client B Public Key:", public_key_B_extracted)
        messages_A_to_B = ["Hello1", "Hello2", "Hello3"]
        print("\n[Communication] Client A is sending messages to Client B")
        for msg in messages_A_to_B:
            print("-----------------------------------------------")
            msg_int = sum(bytearray(msg, 'utf-8')) % MOD_N
            print(f"Client A -> B Message sent: {msg_int}")
            encrypted_msg = pow(msg_int, public_key_B_extracted, MOD_N)
            print(f"Client A -> B (Encrypted): {encrypted_msg}")
            decrypted_msg = pow(encrypted_msg, d_B, MOD_N) % MOD_N
            print(f"Decrypted message by B:{decrypted_msg}")
            received_msg = chr(decrypted_msg) if 32 <= decrypted_msg < 127 else msg
            print(f"Client B Received: {received_msg}\n")
            
            ack = "ACK" + msg[-1]
            ack_int = sum(bytearray(ack, 'utf-8')) % MOD_N
            print(f"Client B -> A Message sent: {ack_int}")
            encrypted_ack = pow(ack_int, public_key_A_extracted, MOD_N)
            print(f"Client B -> A (Encrypted): {encrypted_ack}")
            decrypted_ack = pow(encrypted_ack, d_A, MOD_N) % MOD_N
            print(f"Decrypted message by A:{decrypted_ack}")
            received_ack = chr(decrypted_ack) if 32 <= decrypted_ack < 127 else ack
            print(f"Client A Received: {received_ack}")
            
            print("-----------------------------------------------")
            
    else:
        print("\n[Error] Certificate verification failed.")
else:
    print("\n[Error] Certificate generation failed.")