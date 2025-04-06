# Simplified MD5 implementation (not optimized) — just for MAC demo

import struct

# Left rotate a 32-bit integer
def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

# Initial MD5 constants
INIT_A = 0x67452301
INIT_B = 0xEFCDAB89
INIT_C = 0x98BADCFE
INIT_D = 0x10325476

# Sine-derived constants
K = [int(abs(__import__('math').sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

# Shift amounts for each operation
S = [7, 12, 17, 22]*4 + [5, 9, 14, 20]*4 + [4, 11, 16, 23]*4 + [6, 10, 15, 21]*4

# The four MD5 auxiliary functions
def F(x, y, z): return (x & y) | (~x & z)
def G(x, y, z): return (x & z) | (y & ~z)
def H(x, y, z): return x ^ y ^ z
def I(x, y, z): return y ^ (x | ~z)

# Function to pad the message to a multiple of 512 bits
def md5_pad(message_bytes):
    original_len = len(message_bytes) * 8
    message_bytes += b'\x80'
    while (len(message_bytes) * 8) % 512 != 448:
        message_bytes += b'\x00'
    message_bytes += struct.pack('<Q', original_len)
    return message_bytes

# Full MD5 algorithm
def md5(message):
    message = md5_pad(bytearray(message.encode()))

    A, B, C, D = INIT_A, INIT_B, INIT_C, INIT_D

    for chunk_offset in range(0, len(message), 64):
        chunk = message[chunk_offset:chunk_offset+64]
        M = list(struct.unpack('<16I', chunk))
        a, b, c, d = A, B, C, D

        for i in range(64):
            if 0 <= i <= 15:
                f = F(b, c, d)
                g = i
            elif 16 <= i <= 31:
                f = G(b, c, d)
                g = (5*i + 1) % 16
            elif 32 <= i <= 47:
                f = H(b, c, d)
                g = (3*i + 5) % 16
            else:
                f = I(b, c, d)
                g = (7*i) % 16

            temp = (a + f + K[i] + M[g]) & 0xFFFFFFFF
            temp = left_rotate(temp, S[i])
            a, d, c, b = d, c, b, (b + temp) & 0xFFFFFFFF

        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    return ''.join(f'{x:02x}' for x in struct.pack('<IIII', A, B, C, D))

# MAC = MD5(key + message)
def compute_md5_mac(message, key):
    return md5(key + message)

# Verify MAC
def verify_md5_mac(message, key, mac_check):
    return compute_md5_mac(message, key) == mac_check

# Test
if __name__ == "__main__":
    message = "secret message"
    key = "sharedkey123"

    mac = compute_md5_mac(message, key)
    print("Message:", message)
    print("Key:", key)
    print("Generated MAC:", mac)

    is_valid = verify_md5_mac(message, key, mac)
    print("MAC is valid?", is_valid)
