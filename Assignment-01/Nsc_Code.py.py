import itertools
import hashlib
import random

def generate_hash(string):
    return hashlib.md5(string.encode()).hexdigest()[:6] 

def encrypt_func(plaintext, key):
    string, hash_val = plaintext
    encryption_table = {OMEGA[i]: key[i] for i in range(len(OMEGA))}
    encrypted_string = ''
    for char in string:
        encrypted_string += encryption_table[char]  
    return encrypted_string

def decrypt_func(ciphertext, key):
    decryption_table = {key[i]: OMEGA[i] for i in range(len(OMEGA))}
    decrypted_string = ''
    for char in ciphertext:
        decrypted_string += decryption_table[char]  
    return decrypted_string

def brute_force_attack(ciphertexts, plaintexts):
    for combo in itertools.permutations(OMEGA):
        key = list(combo)
        found =0
        for i, ciphertext in enumerate(ciphertexts):
            decrypted_text = decrypt_func(ciphertext, key)
            ostring,ohash = plaintexts[i]
            if generate_hash(decrypted_text) == ohash:
                found =1
                break
        if found ==1 :
            print(f"Key found: {''.join(key)}")
            return key
    return None

def main(plaintexts: list, ekey: str) -> int:
    ciphertexts = [encrypt_func(pt, ekey) for pt in plaintexts]
    print("\nCiphertexts:", ciphertexts)
    discovered_key = brute_force_attack(ciphertexts, plaintexts)
    return 1 if discovered_key else 0

if __name__ == "__main__":
    OMEGA = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
    original_strings = ["ABCDEFGH", "HGFEDCBA", "FACEGBDH", "BACDGHEF", "GHEFACBD"]
    plaintexts = []
    for s in original_strings:
        hashval = generate_hash(s) 
        plaintexts.append((s, hashval))  
    print("Plaintexts (string, hash):", plaintexts)
    key_used = random.sample(OMEGA, len(OMEGA))
    if main(plaintexts,key_used) == 1:
        print("all texts decrpyted with key")
    else:
        print("Cannot find key")
        