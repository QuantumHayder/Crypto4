# ElGamal and Diffie-Hellman shared parameters
# Using safe primes from IETF RFC 3526 (scaled down for coursework)
# These are pre-computed safe primes: p = 2q + 1 where both p and q are prime

ELGAMAL_PARAMS = {
    "p": 23,        # Safe prime: 2 * 11 + 1
    "alpha": 5,     # Generator of the subgroup of order q = 11
}

DH_PARAMS = {
    "q": 11,    # Prime order
    "p": 23,    # Safe prime: 2q + 1
    "alpha": 5, # Primitive root (generator)
}
