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


def sign_vault(vault_path: str | Path, public_key, private_key) -> tuple:
    """
    Sign the vault file and store the signature inside it.

    Process:
        1. Read the vault JSON file and extract the encrypted_vault content.
        2. Compute H = SHA-256(encrypted_vault) mod (p-1).
        3. Pick random ephemeral k where 1 < k < p-1 and gcd(k, p-1) == 1.
        4. Compute r = g^k mod p.
        5. Compute s = k^-1 * (H - x*r) mod (p-1).
        6. Write r and s back into the vault JSON file under "signature".

    Args:
        vault_path  : Path to the vault JSON file.
        public_key  : ElGamalPublicKey with fields p, g, y.
        private_key : ElGamalPrivateKey with field x.

    Returns:
        (r, s) as a tuple of hex strings.

    Raises:
        FileNotFoundError : If the vault file does not exist.
        KeyError          : If the vault file has no "encrypted_vault" field.
    """
    path = Path(vault_path)
    vault = json.loads(path.read_text(encoding="utf-8"))

    encrypted_vault = vault["encrypted_vault"]

    p = public_key.p
    g = public_key.g
    x = private_key.x
    p_minus_1 = p - 1

    H = int(hash_string(encrypted_vault), 16) % p_minus_1

    # Pick ephemeral k coprime with (p-1)
    while True:
        k = secrets.randbelow(p_minus_1 - 2) + 2   # k in [2, p-2]
        if _gcd(k, p_minus_1) == 1:
            break

    r = pow(g, k, p)

    # s = k^-1 * (H - x*r) mod (p-1)
    k_inv = _mod_inverse(k, p_minus_1)
    s = (k_inv * (H - x * r)) % p_minus_1

    r_hex, s_hex = hex(r), hex(s)

    # Store signature back into the vault file
    vault["signature"] = {"r": r_hex, "s": s_hex}
    path.write_text(json.dumps(vault, indent=2), encoding="utf-8")

    return r_hex, s_hex


if __name__ == "__main__":
    import json
    from pathlib import Path
    from modules.elgamal import ElGamalPublicKey, ElGamalPrivateKey
    from modules.verify import verify_vault

    # Create a sample vault file for testing
    sample_vault = {"encrypted_vault": "a3f8b2c1d4e5_sample_encrypted_data", "signature": {}}
    Path("test_vault.json").write_text(json.dumps(sample_vault, indent=2))

    pub  = ElGamalPublicKey(p=23, g=5, y=17)
    priv = ElGamalPrivateKey(x=7)

    r, s = sign_vault("test_vault.json", pub, priv)
    print("r =", r)
    print("s =", s)
    print("Vault file after signing:")
    print(Path("test_vault.json").read_text())
    print("Verifies:", verify_vault("test_vault.json", pub))