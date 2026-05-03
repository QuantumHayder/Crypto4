import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from modules.config     import DH_PARAMS
from modules.encryption import AES_Encryption
from modules.sign       import sign_message, sign_vault
from modules.verify     import verify_message, verify_vault


@dataclass(frozen=True)
class DHPublicKey:
    value: int
@dataclass(frozen=True)
class DHPrivateKey:
    value: int

def dh_generate_keypair():
    """
    generate an DH keypair from shared config params
    private key chosen from [2, q-1], public key = alpha^private mod p
    """
    q     = DH_PARAMS["q"]
    p     = DH_PARAMS["p"]
    alpha = DH_PARAMS["alpha"]

    private = secrets.randbelow(q - 2) + 2
    public  = pow(alpha, private, p)

    return DHPublicKey(value=public), DHPrivateKey(value=private)


def dh_make_shared_secret(their_public: DHPublicKey, my_private: DHPrivateKey) -> int:
    """
    shared secret = their_public^my_private mod p
    both sides arrive at alpha^(ab) mod p independently
    """
    p = DH_PARAMS["p"]
    return pow(their_public.value, my_private.value, p)

def dh_make_session_key(shared_secret: int) -> str:
    """derive a 256-bit AES session key from the DH shared secret via SHA-256"""
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder="big")
    return hashlib.sha256(secret_bytes).hexdigest()

def sign_dh_public_key(dh_pub: DHPublicKey, public_key, private_key) -> dict:
    """
    sign a DH public key with the sender's ElGamal private key
    so the receiver can verify it wasn't swapped by a MITM
    """
    r, s = sign_message(str(dh_pub.value), public_key, private_key)
    return {
        "dh_public": dh_pub.value,
        "r": format(r, "x"),
        "s": format(s, "x"),
    }

def verify_dh_public_key(signed_pkg: dict, public_key) -> DHPublicKey:
    """
    verify the ElGamal signature on a received DH public key package
    raises ValueError and aborts the exchange if invalid
    """
    dh_value = signed_pkg["dh_public"]
    r = int(signed_pkg["r"], 16)
    s = int(signed_pkg["s"], 16)

    if not verify_message(str(dh_value), r, s, public_key):
        raise ValueError("DH key exchange aborted: signature on DH public key is INVALID")

    return DHPublicKey(value=dh_value)

def sign_export_package(encrypted_data: str, public_key, private_key) -> dict:
    """sign the session-encrypted vault string with D1's ElGamal private key"""
    r, s = sign_message(encrypted_data, public_key, private_key)
    return {
        "encrypted_vault": encrypted_data,
        "r": format(r, "x"),
        "s": format(s, "x"),
    }

def verify_export_package(pkg: dict, sender_public_key) -> str:
    """
    verify the ElGamal signature on the export package using D1's public key
    raises ValueError and aborts import if invalid
    """
    encrypted_data = pkg["encrypted_vault"]
    r = int(pkg["r"], 16)
    s = int(pkg["s"], 16)

    if not verify_message(encrypted_data, r, s, sender_public_key):
        raise ValueError(
            "Import aborted: signature on export package is INVALID — "
            "vault data may have been tampered with in transit"
        )
    return encrypted_data

def device1_start_exchange(public_key, private_key) -> tuple:
    """
    device 1 generates an ephemeral DH keypair and signs the public key
    returns (dh_pub, dh_priv, signed_pkg_to_send_to_device2)
    """
    dh_pub, dh_priv = dh_generate_keypair()
    signed_pkg      = sign_dh_public_key(dh_pub, public_key, private_key)
    return dh_pub, dh_priv, signed_pkg

def device2_respond_to_exchange(d1_signed_pkg, d1_public_key, d2_public_key, d2_private_key) -> tuple:
    """
    device 2 verifies D1's signed DH key, then generates its own and signs it
    aborts with ValueError if D1's signature is invalid
    returns (dh_pub, dh_priv, signed_pkg_to_send_back)
    """
    verify_dh_public_key(d1_signed_pkg, d1_public_key)

    dh_pub, dh_priv = dh_generate_keypair()
    signed_pkg      = sign_dh_public_key(dh_pub, d2_public_key, d2_private_key)
    return dh_pub, dh_priv, signed_pkg

def export_vault(vault_path, master_password, d1_dh_priv, d2_signed_pkg, d1_public_key, d1_private_key, d2_public_key) -> dict:
    """
    build the signed export package on device 1

    verify D2's signed DH public key
    compute shared secret -> derive session AES key
    verify vault integrity before exporting
    decrypt vault with master password
    re-encrypt with session key
    sign the session-encrypted data with D1's ElGamal key
    """
    d2_dh_pub     = verify_dh_public_key(d2_signed_pkg, d2_public_key)
    shared_secret = dh_make_shared_secret(d2_dh_pub, d1_dh_priv)
    session_key   = dh_make_session_key(shared_secret)
    path = Path(vault_path)
    if not verify_vault(path, d1_public_key):
        raise ValueError("Vault signature invalid — refusing to export a tampered vault.")

    vault_dict      = json.loads(path.read_text(encoding="utf-8"))
    plaintext_vault = AES_Encryption(master_password).decrypt(vault_dict["encrypted_vault"])

    session_encrypted = AES_Encryption(session_key).encrypt(plaintext_vault)
    return sign_export_package(session_encrypted, d1_public_key, d1_private_key)


def import_vault(export_pkg, d2_dh_priv, d1_signed_dh_pkg, d1_public_key, d2_public_key, d2_private_key, new_master_password, output_vault_path) -> Path:
    """
    import the exported vault on device 2

    re-derive shared secret from D1's DH public key
    derive the same session key
    verify ElGamal signature on the export package
    decrypt with session key
    re-encrypt with device 2's new master password
    save to disk and sign with D2's ElGamal private key
    """
    d1_dh_pub     = verify_dh_public_key(d1_signed_dh_pkg, d1_public_key)
    shared_secret = dh_make_shared_secret(d1_dh_pub, d2_dh_priv)
    session_key   = dh_make_session_key(shared_secret)

    session_encrypted = verify_export_package(export_pkg, d1_public_key)
    plaintext_vault   = AES_Encryption(session_key).decrypt(session_encrypted)

    new_encrypted = AES_Encryption(new_master_password).encrypt(plaintext_vault)
    output_path   = Path(output_vault_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps({"encrypted_vault": new_encrypted, "signature": {}}, indent=2),
        encoding="utf-8"
    )

    sign_vault(output_path, d2_public_key, d2_private_key)
    return output_path

def build_export_bundle(sender: str, recipient: str, master_password: str) -> dict:
    """
    Run the full DH exchange on behalf of both parties (single-device),
    encrypt the sender's vault under the session key, and return a JSON-
    serialisable bundle the recipient can later import.
    """
    from modules.elgamal import load_keypair

    d1_pub_k, d1_priv_k = load_keypair(sender)
    d2_pub_k, d2_priv_k = load_keypair(recipient)

    _, d1_dh_priv, d1_signed_pkg = device1_start_exchange(d1_pub_k, d1_priv_k)
    _, d2_dh_priv, d2_signed_pkg = device2_respond_to_exchange(
        d1_signed_pkg, d1_pub_k, d2_pub_k, d2_priv_k
    )

    vault_path = Path(f"vaults/{sender}/vault.json")
    export_pkg = export_vault(
        vault_path, master_password,
        d1_dh_priv, d2_signed_pkg,
        d1_pub_k, d1_priv_k, d2_pub_k,
    )

    return {
        "sender": sender,
        "d1_signed_dh_pkg": d1_signed_pkg,
        "d2_dh_priv": d2_dh_priv.value,
        "export_pkg": export_pkg,
    }


def receive_import_bundle(bundle: dict, recipient_username: str, new_master_password: str) -> str:
    """
    Verify signatures, re-derive the shared secret, decrypt the bundle,
    and re-encrypt+save the vault under new_master_password.
    Returns the sender's username.
    """
    from modules.elgamal import load_keypair, load_public_key_only

    sender = bundle["sender"]
    d1_pub_k = load_public_key_only(sender)
    d2_pub_k, d2_priv_k = load_keypair(recipient_username)

    d2_dh_priv = DHPrivateKey(value=bundle["d2_dh_priv"])
    output_path = Path(f"vaults/{recipient_username}/vault.json")

    import_vault(
        bundle["export_pkg"],
        d2_dh_priv,
        bundle["d1_signed_dh_pkg"],
        d1_pub_k,
        d2_pub_k,
        d2_priv_k,
        new_master_password,
        output_path,
    )
    return sender