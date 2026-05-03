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
from cryptography.hazmat.primitives.asymmetric import dh


def generate_safe_prime(bits=2048):
    """
    generate a safe prime p = 2q + 1 using OpenSSL via the cryptography library.
    this is the only practical way to do 2048-bit safe primes in reasonable time
    (~20-30s). pure-python sympy isprime on 2049-bit numbers is too slow.
    """
    params = dh.generate_parameters(generator=2, key_size=bits)
    p = params.parameter_numbers().p
    q = (p - 1) // 2  # p is a safe prime so q is guaranteed prime
    return p, q


def find_generator(p, q):
    """
    find a generator of the subgroup of order q in Z*_p.
    for safe prime p = 2q + 1, pick random candidates and check:
        alpha^q == 1 (mod p) -- order divides q
        alpha^2 != 1 (mod p) -- not +-1, so order is exactly q
    converges in a few tries on average.
    """
    while True:
        alpha = random.randint(2, p - 2)
        if pow(alpha, q, p) == 1 and pow(alpha, 2, p) != 1:
            return alpha


# generate once at import time — ElGamal and DH share the same group
_p, _q = generate_safe_prime(bits=2048)
_alpha  = find_generator(_p, _q)

ELGAMAL_PARAMS = {
    "p":     _p,
    "alpha": _alpha,
}

DH_PARAMS = {
    "q":     _q,
    "p":     _p,
    "alpha": _alpha,
}