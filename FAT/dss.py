import secrets

class DigitalSignature:
    def __init__(self):
        self.p = 23  # Prime modulus
        self.q = 11  # Prime divisor of p-1
        self.g = 4   # Generator
        self.private_key = None
        self.public_key = None

    def _power_mod(self, base, exp, mod):
        result = 1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1:
                result = (result * base) % mod
            exp = exp >> 1
            base = (base * base) % mod
        return result

    def _compute_modular_inverse(self, a, m):
        def extended_gcd(a, b):
            if b == 0:
                return a, 1, 0
            gcd, x1, y1 = extended_gcd(b, a % b)
            x = y1
            y = x1 - (a // b) * y1
            return gcd, x, y

        gcd, x, y = extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Inverse doesn't exist")
        return x % m

    def _hash_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')

        h0, h1, h2, h3, h4 = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        )

        original_length = len(message) * 8
        message += b'\x80'
        while (len(message) * 8 + 64) % 512 != 0:
            message += b'\x00'
        message += original_length.to_bytes(8, 'big')

        for chunk in range(0, len(message), 64):
            block = message[chunk:chunk+64]
            words = [int.from_bytes(block[i:i+4], 'big') 
                    for i in range(0, 64, 4)]

            for i in range(16, 80):
                word = words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]
                words.append((word << 1) | (word >> 31))

            a, b, c, d, e = h0, h1, h2, h3, h4

            for i in range(80):
                if 0 <= i < 20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i < 40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i < 60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = (self._power_mod(a, 5, 0xFFFFFFFF) + f + e + k + words[i]) & 0xFFFFFFFF
                e, d, c, b, a = d, c, ((b << 30) | (b >> 2)) & 0xFFFFFFFF, a, temp

            h0 = (h0 + a) & 0xFFFFFFFF
            h1 = (h1 + b) & 0xFFFFFFFF
            h2 = (h2 + c) & 0xFFFFFFFF
            h3 = (h3 + d) & 0xFFFFFFFF
            h4 = (h4 + e) & 0xFFFFFFFF

        return (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4

    def generate_keys(self):
        self.private_key = secrets.randbelow(self.q - 1) + 1
        self.public_key = self._power_mod(self.g, self.private_key, self.p)
        return self.private_key, self.public_key

    def sign(self, message):
        if not self.private_key:
            raise ValueError("Private key not generated")

        message_hash = self._hash_message(message)
        
        while True:
            k = secrets.randbelow(self.q - 1) + 1
            r = self._power_mod(self.g, k, self.p) % self.q
            if r == 0:
                continue
            
            try:
                s = (self._compute_modular_inverse(k, self.q) * 
                     (message_hash + self.private_key * r)) % self.q
            except ValueError:
                continue
                
            if s == 0:
                continue
                
            return (r, s)

    def verify(self, message, signature):
        if not self.public_key:
            raise ValueError("Public key not available")

        r, s = signature
        if not (0 < r < self.q and 0 < s < self.q):
            return False

        message_hash = self._hash_message(message)
        w = self._compute_modular_inverse(s, self.q)
        u1 = (message_hash * w) % self.q
        u2 = (r * w) % self.q
        
        v = (self._power_mod(self.g, u1, self.p) * 
             self._power_mod(self.public_key, u2, self.p)) % self.p % self.q

        return v == r


if __name__ == "__main__":
    dsa = DigitalSignature()
    priv_key, pub_key = dsa.generate_keys()
    
    print(f"Private Key: {priv_key}")
    print(f"Public Key: {pub_key}")
    
    msg = "Hello, secure world!"
    sig = dsa.sign(msg)
    print(f"Signature (r, s): {sig}")
    
    is_valid = dsa.verify(msg, sig)
    print(f"Signature valid: {is_valid}")
