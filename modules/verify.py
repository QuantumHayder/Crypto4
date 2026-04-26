import json
from pathlib import Path
from modules.hash import hash_string


def verify_vault(vault_path: str | Path, public_key) -> bool:
    """
    Verify the ElGamal digital signature stored inside the vault file.

    Verification equation (must hold for a valid signature):
        g^H ≡ y^r * r^s  (mod p)

    where H = SHA-256(encrypted_vault) mod (p-1).

    Process:
        1. Read the vault JSON file.
        2. Extract encrypted_vault content and stored signature (r, s).
        3. Recompute H = SHA-256(encrypted_vault) mod (p-1).
        4. Check g^H ≡ y^r * r^s (mod p).

    Args:
        vault_path : Path to the vault JSON file.
        public_key : ElGamalPublicKey with fields p, g, y.

    Returns:
        True  — signature valid, vault is untampered.
        False — signature invalid, vault may have been tampered with.

    Raises:
        FileNotFoundError : If the vault file does not exist.
        KeyError          : If the vault file is missing required fields.
    """
    path = Path(vault_path)
    vault = json.loads(path.read_text(encoding="utf-8"))

    encrypted_vault = vault["encrypted_vault"]
    signature = vault["signature"]
    r = int(signature["r"], 16)
    s = int(signature["s"], 16)

    p = public_key.p
    g = public_key.g
    y = public_key.y
    p_minus_1 = p - 1

    # Sanity checks on signature components
    if not (0 < r < p):
        return False
    if not (0 < s < p_minus_1):
        return False

    H = int(hash_string(encrypted_vault), 16) % p_minus_1

    lhs = pow(g, H, p)                        # g^H mod p
    rhs = (pow(y, r, p) * pow(r, s, p)) % p  # y^r * r^s mod p

    return lhs == rhs


def verify_or_abort(vault_path: str | Path, public_key) -> None:
    """
    Verify the vault signature and raise RuntimeError if invalid.

    Use this every time the vault is opened so a tampered vault
    never exposes credentials.

    Args:
        vault_path : Path to the vault JSON file.
        public_key : ElGamalPublicKey with fields p, g, y.

    Raises:
        RuntimeError: If the signature is invalid.
    """
    if not verify_vault(vault_path, public_key):
        raise RuntimeError(
            "\n⚠️  ALERT: Vault signature verification FAILED!\n"
            "The vault file may have been tampered with.\n"
            "Refusing to open vault."
        )


if __name__ == "__main__":
    import json
    from pathlib import Path
    from modules.elgamal import ElGamalPublicKey, ElGamalPrivateKey
    from modules.sign import sign_vault

    pub  = ElGamalPublicKey(p=23, g=5, y=17)
    priv = ElGamalPrivateKey(x=7)

    # Create and sign a sample vault
    sample_vault = {"encrypted_vault": "a3f8b2c1d4e5_sample_encrypted_data", "signature": {}}
    Path("test_vault.json").write_text(json.dumps(sample_vault, indent=2))
    sign_vault("test_vault.json", pub, priv)

    print("=== Valid signature ===")
    print("Result:", verify_vault("test_vault.json", pub))

    print("\n=== Tampered vault (manual edit) ===")
    vault = json.loads(Path("test_vault.json").read_text())
    vault["encrypted_vault"] = "tampered_data!!"
    Path("test_vault.json").write_text(json.dumps(vault, indent=2))
    print("Result:", verify_vault("test_vault.json", pub))

    print("\n=== verify_or_abort on tampered vault ===")
    try:
        verify_or_abort("test_vault.json", pub)
    except RuntimeError as e:
        print(e)