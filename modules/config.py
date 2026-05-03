# ElGamal and Diffie-Hellman shared parameters
# Using safe primes from IETF RFC 3526 (scaled down for coursework)
# These are pre-computed safe primes: p = 2q + 1 where both p and q are prime

# ELGAMAL_PARAMS = {
#     "p": 23,        # Safe prime: 2 * 11 + 1
#     "alpha": 5,     # Generator of the subgroup of order q = 11
# }

# DH_PARAMS = {
#     "q": 11,    # Prime order
#     "p": 23,    # Safe prime: 2q + 1
#     "alpha": 5, # Primitive root (generator)
# }


import random
from sympy import isprime, nextprime
 
 
def generate_safe_prime(bits=256):
    """
    generate a safe prime p = 2q + 1 where both p and q are prime
    bits controls the size of q
    """
    while True:
        q = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if not isprime(q):
            continue
        p = 2 * q + 1
        if isprime(p):
            return p, q
 
 
def find_generator(p, q):
    """
    find a generator of the subgroup of order q in Z*_p
    for safe prime p = 2q + 1, we need alpha s.t.:
        alpha^q ≡ 1 (mod p)   — element has order q (or 1)
        alpha^2 != 1 (mod p)  — not the identity's square root
        alpha != 1 and alpha != p-1
    
    instead of iterating from 2 upward (way too slow for large p),
    pick random candidates and test them
    """
    while True:
        alpha = random.randint(2, p - 2)
        if pow(alpha, q, p) == 1 and pow(alpha, 2, p) != 1:
            return alpha
 
 
def _generate_params(bits=256):
    p, q = generate_safe_prime(bits)
    alpha = find_generator(p, q)
    return p, q, alpha
 

_p, _q, _alpha = _generate_params(bits=256)
 
ELGAMAL_PARAMS = {
    "p":     _p,
    "alpha": _alpha,
}
 
DH_PARAMS = {
    "q":     _q,
    "p":     _p,
    "alpha": _alpha,
}
 