"""
vault_service.py

All business logic for the vault application.
No Streamlit imports — purely data operations.
"""

import json
from pathlib import Path

from modules.elgamal import generate_keypair, save_keypair, load_keypair
from modules.encryption import AES_Encryption
from modules.sign import sign_vault
from modules.verify import verify_vault

VAULTS_DIR = Path("vaults")


# ── path helpers ──

def vault_path(username: str) -> Path:
    return VAULTS_DIR / username / "vault.json"

def user_exists(username: str) -> bool:
    return vault_path(username).exists()


# ── account management ──

def register_user(username: str, master_password: str) -> None:
    """
    Generate ElGamal keypair, save it, and create an empty signed vault.

    Raises:
        ValueError: if username is taken or keypair generation fails.
    """
    pub, priv = generate_keypair(username)
    save_keypair(pub, priv, username)
    _init_vault(username, master_password, pub, priv)


def _init_vault(username: str, master_password: str, pub, priv) -> None:
    """Create a brand-new empty encrypted and signed vault on disk."""
    path = vault_path(username)
    path.parent.mkdir(parents=True, exist_ok=True)
    empty = json.dumps({"entries": []})
    enc = AES_Encryption(master_password).encrypt(empty)
    path.write_text(
        json.dumps({"encrypted_vault": enc, "signature": {}}, indent=2),
        encoding="utf-8",
    )
    sign_vault(path, pub, priv)


# ── vault operations ──

def load_entries(username: str, master_password: str) -> list[dict]:
    """
    Verify vault signature, decrypt, and return the list of credential entries.

    Raises:
        Exception: on signature failure or wrong master password.
    """
    path = vault_path(username)
    pub, _ = load_keypair(username)

    if not verify_vault(path, pub):
        raise Exception("Vault signature check failed — vault may have been tampered with.")

    data = json.loads(path.read_text(encoding="utf-8"))
    try:
        plain = AES_Encryption(master_password).decrypt(data["encrypted_vault"])
    except Exception:
        raise Exception("Wrong master password.")

    return json.loads(plain)["entries"]


def save_entries(username: str, master_password: str, entries: list[dict]) -> None:
    """Encrypt and sign the updated entries list back to disk."""
    path = vault_path(username)
    enc = AES_Encryption(master_password).encrypt(json.dumps({"entries": entries}))
    path.write_text(
        json.dumps({"encrypted_vault": enc, "signature": {}}, indent=2),
        encoding="utf-8",
    )
    pub, priv = load_keypair(username)
    sign_vault(path, pub, priv)


def verify_master_password(username: str, pw: str) -> bool:
    """Return True if pw correctly decrypts the vault."""
    try:
        load_entries(username, pw)
        return True
    except Exception:
        return False


# ── DH export / import (thin wrappers to keep imports out of UI) ──

def build_export_bundle(sender: str, recipient: str, master_password: str) -> dict:
    """
    Run the full DH key exchange and return a JSON-serialisable bundle dict.

    Raises:
        Exception: on any crypto or key-loading failure.
    """
    from diffie_hellman_export import (
        device1_start_exchange,
        device2_respond_to_exchange,
        export_vault,
        DHPrivateKey,
    )

    d1_pub, d1_priv = load_keypair(sender)
    d2_pub, d2_priv = load_keypair(recipient)

    d1_dh_pub, d1_dh_priv, d1_signed_dh = device1_start_exchange(d1_pub, d1_priv)
    _, d2_dh_priv, d2_signed_dh = device2_respond_to_exchange(
        d1_signed_dh, d1_pub, d2_pub, d2_priv
    )

    pkg = export_vault(
        vault_path=vault_path(sender),
        master_password=master_password,
        d1_dh_priv=d1_dh_priv,
        d2_signed_pkg=d2_signed_dh,
        d1_public_key=d1_pub,
        d1_private_key=d1_priv,
        d2_public_key=d2_pub,
    )

    return {
        "export_pkg":   pkg,
        "d1_signed_dh": d1_signed_dh,
        "d2_dh_priv":   d2_dh_priv.value,
        "sender":       sender,
        "recipient":    recipient,
    }


def receive_import_bundle(
    bundle: dict,
    recipient_username: str,
    new_master_password: str,
) -> str:
    """
    Verify, decrypt, and save an imported vault bundle.

    Returns:
        sender username on success.

    Raises:
        ValueError: if bundle is addressed to a different user.
        Exception: on signature or decryption failure.
    """
    from diffie_hellman_export import import_vault, DHPrivateKey

    if bundle["recipient"] != recipient_username:
        raise ValueError(
            f"This bundle is addressed to '{bundle['recipient']}', not you."
        )

    sender = bundle["sender"]
    d1_pub, _       = load_keypair(sender)
    d2_pub, d2_priv = load_keypair(recipient_username)

    import_vault(
        export_pkg=bundle["export_pkg"],
        d2_dh_priv=DHPrivateKey(value=bundle["d2_dh_priv"]),
        d1_signed_dh_pkg=bundle["d1_signed_dh"],
        d1_public_key=d1_pub,
        d2_public_key=d2_pub,
        d2_private_key=d2_priv,
        new_master_password=new_master_password,
        output_vault_path=vault_path(recipient_username),
    )

    return sender
