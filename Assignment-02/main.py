initial_perm= [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

final_perm = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

Exp_tab = [
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1
]

perm_tab = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

S_BOX = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
 
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
 
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
 
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
 
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
 
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
 
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
 
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

def hex_to_bin(hex_str):
    return bin(int(hex_str, 16))[2:].zfill(64)

def bin_to_hex(bin_str):
    return hex(int(bin_str, 2))[2:].upper().zfill(16)

def myxorfunc(bin_arr1, bin_arr2):
    xor_result = [int(bit1) ^ int(bit2) for bit1, bit2 in zip(bin_arr1, bin_arr2)]
    return xor_result

def initial_permutation(binary_input):
    step1 = []
    for i in initial_perm:
        step1.append(int(binary_input[i-1])) 
    return step1

def final_permutation(binary_input):
    step1 = []
    for i in final_perm:
        step1.append(int(binary_input[i-1])) 
    return step1

def expansionbox(R):
    exparr = []
    for i in Exp_tab:
        exparr.append(int(R[i-1]))
    return exparr

def s_box(input, s_box):
    row = int(input[0] + input[5], 2)
    col = int(input[1:5], 2)
    return bin(s_box[row][col])[2:].zfill(4)

def myffunc(Rp, subkey):
    expandedR = expansionbox(Rp)
    xoredout = myxorfunc(expandedR, subkey)
    sbox_split = []
    for i in range(0, 48, 6):
        sbox_split.append(xoredout[i:i+6])
    
    sbox_output = ""
    for i in range(8): 
        sbox_output += s_box(''.join(map(str, sbox_split[i])), S_BOX[i]) 
    
    sboxarr = [int(s) for s in sbox_output]
    fboxout = [sboxarr[i - 1] for i in perm_tab]
    return fboxout

shift_table = [1, 1, 2, 2,
               2, 2, 2, 2,
               1, 2, 2, 2,
               2, 2, 2, 1]

PC1 = [
    57, 49, 41, 33, 25, 17,  9,
    1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
]

PC2 = [
    14, 17, 11, 24,  1,  5,  3, 28,
    15,  6, 21, 10, 23, 19, 12,  4,
    26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

def left_shift(bits, shift_count):
    return bits[shift_count:] + bits[:shift_count]

def myroundkeyfunc(key_bin):
    permuted_key =""
    for i in PC1:
        permuted_key += key_bin[i-1]
    leftside = permuted_key[:28]
    rightside = permuted_key[28:]
    subkeys = []
    for shift in shift_table:
        leftside = left_shift(leftside, shift)
        rightside = left_shift(rightside, shift)
        combined_key = leftside + rightside
        subkey = ""
        for i in PC2:
            subkey += combined_key[i-1]
        subkeys.append(subkey)
    return subkeys

def des_encrypt(plaintext,key):
    bkey = hex_to_bin(key)
    binary_plaintext = hex_to_bin(plaintext)
    initial_perm_text = initial_permutation(binary_plaintext)
    L, R = initial_perm_text[:32], initial_perm_text[32:]
    subkeys = myroundkeyfunc(bkey)
    for i in range(16):
        new_R = myffunc(R, [int(bit) for bit in subkeys[i]])
        new_R = myxorfunc(L, new_R) 
        L, R = R, new_R 
        print("Round No. " + str(i+1))
        print("Subkey for this Round: " + bin_to_hex(subkeys[i]))
        print(f" L: {''.join(map(str, L))} R: {''.join(map(str, new_R))}")

    final_text = final_permutation(R + L)
    return bin_to_hex(''.join(map(str, final_text)))

def des_decrypt(ciphertext,key):
    bkey = hex_to_bin(key)
    binary_ciphertext = hex_to_bin(ciphertext)
    initial_perm_text = initial_permutation(binary_ciphertext)
    subkeys = myroundkeyfunc(bkey)
    subkeys.reverse()
    L, R = initial_perm_text[:32], initial_perm_text[32:]
    print("-----------------------------------------------------")
    print("DECRYPTION STARTED")
    print("-----------------------------------------------------")
    for i in range(16):
        new_R = myffunc(R, [int(bit) for bit in subkeys[i]])
        new_R = myxorfunc(L, new_R)
        L, R = R, new_R
        print("Round No. " + str(i+1))
        print("Subkey for this Round: " + bin_to_hex(subkeys[i]))
        print(f" L: {''.join(map(str, L))} R: {''.join(map(str, new_R))}")

    final_text = final_permutation(R + L) 
    return bin_to_hex(''.join(map(str, final_text)))


def main(plaintext,key):
    ciphertext = des_encrypt(plaintext,key)
    decryptedtext = des_decrypt(ciphertext,key)
    print(f"Plaintext: {plaintext}")
    print(f"Key: {key}")
    print(f"Ciphertext: {ciphertext}")
    print(f"decrypted text: {decryptedtext}")
    
plaintext = "123456ABCD132536"
key = "AABB09182736CCDD"

main(plaintext,key)

