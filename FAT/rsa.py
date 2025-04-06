import random
from math import gcd
def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5)+1):
        if n % i == 0:
            return False
    return True

def generate_keys():
    # Pick two prime numbers
    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)
    # Choose e such that e and phi(n) are coprime
    e = 17
    while gcd(e, phi) != 1:
        e += 2
    # Calculate d
    d = modinv(e, phi)

    return ((e, n), (d, n))  # public key, private key

def encrypt(message, public_key):
    e, n = public_key
    cipher = [(ord(char) ** e) % n for char in message]
    return cipher

def decrypt(cipher, private_key):
    d, n = private_key
    decrypted = [chr((char ** d) % n) for char in cipher]
    return ''.join(decrypted)

if __name__ == "__main__":
    public_key, private_key = generate_keys()
    message = "hello"
    print("Original Message:", message)
    encrypted_msg = encrypt(message, public_key)
    print("Encrypted Message:", encrypted_msg)
    decrypted_msg = decrypt(encrypted_msg, private_key)
    print("Decrypted Message:", decrypted_msg)
