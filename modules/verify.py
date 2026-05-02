import json
from pathlib import Path
from modules.hash import hash_string


def _computeHash(vault_path: str | Path, public_key) -> bool:
    path = Path(vault_path)
    vault = json.loads(path.read_text(encoding="utf-8"))

    encrypted_vault = vault["encrypted_vault"]
    signature = vault["signature"]
    r = int(signature["r"], 16)
    s = int(signature["s"], 16)

    p = public_key.p
    alpha = public_key.alpha
    y = public_key.y
    p_minus_1 = p - 1

    if (not (0 < r < p) or not (0 < s < p_minus_1)):
        return False

    H = int(hash_string(encrypted_vault), 16) % p_minus_1

    lhs = pow(alpha, H, p)                       
    rhs = (pow(y, r, p) * pow(r, s, p)) % p

    return lhs == rhs


def verify_vault(vault_path: str | Path, public_key) -> bool:
    if not _computeHash(vault_path, public_key):
        msg = (
            "\nALERT: Vault signature verification FAILED!\n"
            "The vault file may have been tampered with.\n"
            "Refusing to open vault."
        )
        print(msg)
        return False
    
    print("\nVault signature verification PASSED. Vault is safe to open.")
    return True