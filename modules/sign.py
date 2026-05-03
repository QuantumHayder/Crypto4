import json
import secrets
from pathlib import Path
from modules.hash import hash_string


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _extended_gcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def _mod_inverse(a: int, m: int) -> int:
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse exists: gcd({a}, {m}) = {g}")
    return x % m


def _pick_coprime_k(p_minus_1: int) -> int:
    while True:
        k = secrets.randbelow(p_minus_1 - 2) + 2
        if _gcd(k, p_minus_1) == 1:
            return k


def sign_message(message: str, public_key, private_key) -> tuple[int, int]:
    p = public_key.p
    alpha = public_key.alpha
    x = private_key.x
    p_minus_1 = p - 1

    H = int(hash_string(message), 16) % p_minus_1

    while True:
        k = _pick_coprime_k(p_minus_1)
        r = pow(alpha, k, p)
        k_inv = _mod_inverse(k, p_minus_1)
        s = (k_inv * (H - x * r)) % p_minus_1
        if s != 0:
            return r, s


def sign_vault(vault_path: str | Path, public_key, private_key) -> tuple:
    path = Path(vault_path)
    vault = json.loads(path.read_text(encoding="utf-8"))

    encrypted_vault = vault["encrypted_vault"]

    r, s = sign_message(encrypted_vault, public_key, private_key)
    vault["signature"] = {"r": format(r, "x"), "s": format(s, "x")}

    path.write_text(json.dumps(vault, indent=2), encoding="utf-8")
    return vault

if __name__ == "__main__":
    from modules.elgamal import ElGamalPublicKey, ElGamalPrivateKey
    from modules.verify import verify_vault

    # Create a sample vault file for testing
    sample_vault = {"encrypted_vault": "a3f8b2c1d4e5_sample_encrypted_data", "signature": {}}
    Path("test_vault.json").write_text(json.dumps(sample_vault, indent=2))

    pub  = ElGamalPublicKey(p=23, alpha=5, y=17)
    priv = ElGamalPrivateKey(x=7)

    vault = sign_vault("test_vault.json", pub, priv)
    # print("Vault file after signing:")
    # print(json.dumps(vault, indent=2))
    print("Verifies:", verify_vault("test_vault.json", pub))