# Simple DES encryption and decryption using 64-bit key and 64-bit block

# Initial and Final Permutations (IP and FP)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion table
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# P permutation
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Single S-box replicated 8 times
S_BOX = [[
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]] * 8

def str_to_bin(s):
    return ''.join(format(ord(c), '08b') for c in s)

def bin_to_str(b):
    chars = [chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)]
    return ''.join(chars).rstrip('\x00')  # remove null chars if any

def permute(block, table):
    return ''.join(block[i - 1] for i in table)

def xor(a, b):
    return ''.join('0' if i == j else '1' for i, j in zip(a, b))

def sbox_substitution(bits):
    result = ''
    for i in range(8):
        block = bits[i*6:(i+1)*6]
        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)
        val = S_BOX[i][row][col]
        result += format(val, '04b')
    return result

def feistel(right, key):
    expanded = permute(right, E)
    xored = xor(expanded, key[:48])  # Use first 48 bits of key
    substituted = sbox_substitution(xored)
    return permute(substituted, P)

def des_block(block, key, decrypt=False):
    block = permute(block, IP)
    left, right = block[:32], block[32:]

    round_keys = [key] * 16  # Simplified: same key used in each round
    if decrypt:
        round_keys = round_keys[::-1]  # Reverse key order for decryption

    for rk in round_keys:
        temp = right
        right = xor(left, feistel(right, rk))
        left = temp

    combined = right + left
    return permute(combined, FP)

def des_encrypt(plaintext, key):
    binary_text = str_to_bin(plaintext).ljust(64, '0')[:64]
    binary_key = str_to_bin(key).ljust(64, '0')[:64]
    encrypted = des_block(binary_text, binary_key, decrypt=False)
    return encrypted

def des_decrypt(ciphertext, key):
    binary_key = str_to_bin(key).ljust(64, '0')[:64]
    decrypted_bin = des_block(ciphertext, binary_key, decrypt=True)
    return bin_to_str(decrypted_bin)

if __name__ == "__main__":
    plaintext = "DESdemo"
    key = "64bitkey"
    
    print("Plaintext:", plaintext)
    ciphertext = des_encrypt(plaintext, key)
    print("Encrypted (binary):", ciphertext)
    
    decrypted = des_decrypt(ciphertext, key)
    print("Decrypted:", decrypted)
