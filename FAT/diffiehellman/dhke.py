def modexp(base, exp, mod):
    """Modular exponentiation"""
    result = 1
    for _ in range(exp):
        result = (result * base) % mod
    return result

def legitimate_exchange():
    print(" LEGITIMATE KEY EXCHANGE")
    g = 5
    p = 23

    a = 6  # Alice's private key
    b = 15 # Bob's private key

    A = modexp(g, a, p)
    B = modexp(g, b, p)

    key_alice = modexp(B, a, p)
    key_bob = modexp(A, b, p)

    print(f"Public Base (g): {g}, Prime (p): {p}")
    print(f"Alice's Public (A = g^a mod p): {A}")
    print(f"Bob's Public (B = g^b mod p): {B}")
    print(f"Alice's Shared Key: {key_alice}")
    print(f"Bob's Shared Key:   {key_bob}")
    print(" Keys match!\n" if key_alice == key_bob else " Keys mismatch!\n")

def mitm_attack():
    print(" MITM ATTACK DEMONSTRATION")
    g = 5
    p = 23

    a = 6   # Alice
    b = 15  # Bob
    e = 13  # Eve (attacker)

    A_real = modexp(g, a, p)  # g^a mod p
    B_real = modexp(g, b, p)  # g^b mod p
    E_public = modexp(g, e, p)

    print(f"Public Base (g): {g}, Prime (p): {p}")
    print(f"Alice computes A = {A_real} and sends → Eve intercepts")
    print(f"Eve replaces A with E = {E_public} and sends to Bob")

    print(f"Bob computes B = {B_real} and sends → Eve intercepts")
    print(f"Eve replaces B with E = {E_public} and sends to Alice")

    # Now everyone computes shared keys
    key_alice = modexp(E_public, a, p)   # Alice thinks it's Bob's public
    key_bob = modexp(E_public, b, p)     # Bob thinks it's Alice's public
    key_eve_with_alice = modexp(A_real, e, p)
    key_eve_with_bob = modexp(B_real, e, p)

    print(f"\nShared Keys:")
    print(f"Alice thinks shared key is: {key_alice}")
    print(f"Bob thinks shared key is:   {key_bob}")
    print(f"Eve's key with Alice:       {key_eve_with_alice}")
    print(f"Eve's key with Bob:         {key_eve_with_bob}")

    if key_alice != key_bob:
        print(" Alice and Bob DO NOT share the same key.")
    if key_eve_with_alice == key_alice and key_eve_with_bob == key_bob:
        print(" Eve has successfully performed a MITM attack!")

# Run both demonstrations
legitimate_exchange()
mitm_attack()
