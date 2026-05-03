import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from modules.config     import DH_PARAMS
from modules.encryption import AES_Encryption
from modules.hash       import hash_string
from modules.sign       import _gcd, _mod_inverse, _pick_coprime_k
from modules.sign       import sign_vault
from modules.verify     import verify_vault


@dataclass(frozen=True)
class DHPublicKey:
    value: int  # alpha^private mod p

@dataclass(frozen=True)
class DHPrivateKey:
    value: int


# DH core

def dh_generate_keypair():
    """
    generate an ephemeral DH keypair from shared config params
    private key chosen from [2, q-1], public key = alpha^private mod p
    """
    q     = DH_PARAMS["q"]
    p     = DH_PARAMS["p"]
    alpha = DH_PARAMS["alpha"]

    private = secrets.randbelow(q - 2) + 2
    public  = pow(alpha, private, p)

    return DHPublicKey(value=public), DHPrivateKey(value=private)


def dh_compute_shared_secret(their_public: DHPublicKey, my_private: DHPrivateKey) -> int:
    """
    shared secret = their_public^my_private mod p
    both sides arrive at alpha^(ab) mod p independently
    """
    p = DH_PARAMS["p"]
    return pow(their_public.value, my_private.value, p)


def dh_derive_session_key(shared_secret: int) -> str:
    """derive a 256-bit AES session key from the DH shared secret via SHA-256"""
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8,
        byteorder="big"
    )
    return hashlib.sha256(secret_bytes).hexdigest()


# ElGamal signing helpers (DH public key + export package)

def _elgamal_sign(message_str: str, public_key, private_key) -> tuple[int, int]:
    """
    sign an arbitrary string with ElGamal using the key pair from Module 1
    returns (r, s) — raises if s ends up 0 (retry k)
    """
    p         = public_key.p
    alpha     = public_key.alpha
    x         = private_key.x
    p_minus_1 = p - 1

    H = int(hash_string(message_str), 16) % p_minus_1

    # retry if s == 0 (happens when H == x*r mod p-1)
    while True:
        k     = _pick_coprime_k(p_minus_1)
        r     = pow(alpha, k, p)
        k_inv = _mod_inverse(k, p_minus_1)
        s     = (k_inv * (H - x * r)) % p_minus_1
        if s != 0:
            return r, s


def _elgamal_verify(message_str: str, r: int, s: int, public_key) -> bool:
    """verify an ElGamal signature produced by _elgamal_sign"""
    p         = public_key.p
    alpha     = public_key.alpha
    y         = public_key.y
    p_minus_1 = p - 1

    if not (0 < r < p) or not (0 < s < p_minus_1):
        return False

    H   = int(hash_string(message_str), 16) % p_minus_1
    lhs = pow(alpha, H, p)
    rhs = (pow(y, r, p) * pow(r, s, p)) % p
    return lhs == rhs


# sign / verify DH public keys

def sign_dh_public_key(dh_pub: DHPublicKey, public_key, private_key) -> dict:
    """
    sign a DH public key with the sender's ElGamal private key (Module 1)
    so the receiver can verify it wasn't swapped by a MITM
    """
    r, s = _elgamal_sign(str(dh_pub.value), public_key, private_key)
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

    if not _elgamal_verify(str(dh_value), r, s, public_key):
        raise ValueError("DH key exchange aborted: signature on DH public key is INVALID")

    return DHPublicKey(value=dh_value)


# sign / verify the export package

def _sign_export_package(encrypted_data: str, public_key, private_key) -> dict:
    """sign the session-encrypted vault string with D1's ElGamal private key"""
    r, s = _elgamal_sign(encrypted_data, public_key, private_key)
    return {
        "encrypted_vault": encrypted_data,
        "r": format(r, "x"),
        "s": format(s, "x"),
    }


def _verify_export_package(pkg: dict, sender_public_key) -> str:
    """
    verify the ElGamal signature on the export package using D1's public key
    raises ValueError and aborts import if invalid
    """
    encrypted_data = pkg["encrypted_vault"]
    r = int(pkg["r"], 16)
    s = int(pkg["s"], 16)

    if not _elgamal_verify(encrypted_data, r, s, sender_public_key):
        raise ValueError(
            "Import aborted: signature on export package is INVALID — "
            "vault data may have been tampered with in transit"
        )

    return encrypted_data


# key exchange

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
    aborts with ValueError if D1's signature is invalid (spec step 4)
    returns (dh_pub, dh_priv, signed_pkg_to_send_back)
    """
    # spec step 4: verify D1's signature — abort if invalid
    verify_dh_public_key(d1_signed_pkg, d1_public_key)

    dh_pub, dh_priv = dh_generate_keypair()
    signed_pkg      = sign_dh_public_key(dh_pub, d2_public_key, d2_private_key)
    return dh_pub, dh_priv, signed_pkg


# transfer & import

def export_vault(vault_path, master_password, d1_dh_priv, d2_signed_pkg,
                 d1_public_key, d1_private_key, d2_public_key) -> dict:
    """
    build the signed export package on device 1 (spec Transfer Phase)

    1. verify D2's signed DH public key (spec step 6)
    2. compute shared secret -> derive session AES key (spec step 7-8)
    3. verify vault integrity before exporting
    4. decrypt vault with master password (in memory only, spec step 1-2)
    5. re-encrypt with session key (spec step 3)
    6. sign the session-encrypted data with D1's ElGamal key (spec step 4)
    """
    # spec step 6: verify D2's signature on its DH public key, abort if invalid
    d2_dh_pub     = verify_dh_public_key(d2_signed_pkg, d2_public_key)
    shared_secret = dh_compute_shared_secret(d2_dh_pub, d1_dh_priv)
    session_key   = dh_derive_session_key(shared_secret)

    # verify vault integrity before touching it
    path = Path(vault_path)
    if not verify_vault(path, d1_public_key):
        raise ValueError("Vault signature invalid — refusing to export a tampered vault.")

    vault_dict      = json.loads(path.read_text(encoding="utf-8"))
    plaintext_vault = AES_Encryption(master_password).decrypt(vault_dict["encrypted_vault"])

    # re-encrypt with session key then sign (spec steps 3-4)
    session_encrypted = AES_Encryption(session_key).encrypt(plaintext_vault)
    return _sign_export_package(session_encrypted, d1_public_key, d1_private_key)


def import_vault(export_pkg, d2_dh_priv, d1_signed_dh_pkg, d1_public_key,
                 d2_public_key, d2_private_key, new_master_password, output_vault_path) -> Path:
    """
    import the exported vault on device 2 (spec Import Phase)

    1. re-derive shared secret from D1's DH public key (spec step 1)
    2. derive the same session key (spec step 1)
    3. verify ElGamal signature on the export package (spec step 6 transfer phase)
    4. decrypt with session key (spec step 2)
    5. re-encrypt with device 2's new master password (spec step 3-4)
    6. save to disk and sign with D2's ElGamal private key (spec step 5)
    """
    # re-derive shared secret — D2 uses D1's DH public key with its own private key
    d1_dh_pub     = verify_dh_public_key(d1_signed_dh_pkg, d1_public_key)
    shared_secret = dh_compute_shared_secret(d1_dh_pub, d2_dh_priv)
    session_key   = dh_derive_session_key(shared_secret)

    # spec: verify D1's signature on the package, abort if invalid
    session_encrypted = _verify_export_package(export_pkg, d1_public_key)
    plaintext_vault   = AES_Encryption(session_key).decrypt(session_encrypted)

    # re-encrypt under D2's master password and save
    new_encrypted = AES_Encryption(new_master_password).encrypt(plaintext_vault)
    output_path   = Path(output_vault_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps({"encrypted_vault": new_encrypted, "signature": {}}, indent=2),
        encoding="utf-8"
    )

    # sign with D2's key (spec import phase step 5)
    sign_vault(output_path, d2_public_key, d2_private_key)
    return output_path