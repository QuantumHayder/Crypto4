import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from modules.config import ELGAMAL_PARAMS

DEFAULT_KEYS_DIR = Path("vaults")


def _user_private_key_path(username: str) -> Path:
	return DEFAULT_KEYS_DIR / f"{username}" / "keys" / f"{username}_private.json"

def _user_public_key_path(username: str) -> Path:
	return DEFAULT_KEYS_DIR / f"{username}" / "keys" / f"{username}_public.json"

def _require_int_field(section: dict, name: str) -> int:
    value = section.get(name)
    if value is None:
        raise ValueError(f"Missing field: {name}")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid integer field: {name}") from exc


@dataclass(frozen=True)
class ElGamalPublicKey:
	p: 		int
	alpha: 	int
	y: 		int


@dataclass(frozen=True)
class ElGamalPrivateKey:
	x: int


def generate_keypair(username: str):
	"""
	generate an elgamal keypair using shared parameters from config
	
	returns:
		(ElGamalPublicKey, ElGamalPrivateKey)

	raises:
		ValueError: if username is invalid or keys already exist for this user
	"""
	if not username or not isinstance(username, str):
		raise ValueError("username must be a non-empty string")
	
	key_path = _user_private_key_path(username)
	if key_path.exists():
		raise ValueError(f"Keys already exist for user '{username}'. Use load_keypair() to load them.")
	
	p 	  = ELGAMAL_PARAMS["p"]
	alpha = ELGAMAL_PARAMS["alpha"]
	
	x = secrets.randbelow(p - 3) + 2   # [2, p-2]
	
	# y = alpha^x mod p
	y = pow(alpha, x, p)
	
	return ElGamalPublicKey(p=p, alpha=alpha, y=y), ElGamalPrivateKey(x=x)


def validate_keypair(public_key: ElGamalPublicKey, private_key: ElGamalPrivateKey) -> None:
	"""
	validate that a keypair is mathematically consistent

	raises:
		ValueError: if any validation check fails.
	"""
	if public_key.p <= 2:
		raise ValueError("Invalid prime modulus")
	
	if public_key.alpha <= 1 or public_key.alpha >= public_key.p:
		raise ValueError("Invalid primitive root")
	
	if public_key.y <= 1 or public_key.y >= public_key.p:
		raise ValueError("Invalid public key value")
	
	if private_key.x <= 1 or private_key.x >= public_key.p - 1:
		raise ValueError("Invalid private key value")
	
	if pow(public_key.alpha, private_key.x, public_key.p) != public_key.y:
		raise ValueError("Public and private key values do not match")


def save_keypair(
	public_key: ElGamalPublicKey,
	private_key: ElGamalPrivateKey,
	username: str
) -> tuple[Path, Path]:
	"""
	save keypair to JSON file

	returns:
		tuple[Path, Path]: paths where (private_key, public_key) were saved.
	"""
	if not username or not isinstance(username, str):
		raise ValueError("username must be a non-empty string")
	
	validate_keypair(public_key, private_key)

	private_path = _user_private_key_path(username)
	public_path  = _user_public_key_path(username)
	
	private_path.parent.mkdir(parents=True, exist_ok=True)
	public_path.parent.mkdir(parents=True, exist_ok=True)

	private_payload = {
		"private": {
			"x": str(private_key.x),
		}
	}

	public_payload = {
		"public": {
			"p":     str(public_key.p),
			"alpha": str(public_key.alpha),
			"y":     str(public_key.y),
		}
	}

	private_path.write_text(json.dumps(private_payload, indent=2), encoding="utf-8")
	public_path.write_text(json.dumps(public_payload,  indent=2), encoding="utf-8")
	
	return private_path, public_path


def load_keypair(username: str):
	"""
	load keypair from JSON file and validate it

	returns:
		(ElGamalPublicKey, ElGamalPrivateKey): The loaded keypair

	raises:
		FileNotFoundError
		ValueError: If the key file is invalid or keys don't match
	"""
	if not username or not isinstance(username, str):
		raise ValueError("username must be a non-empty string")
	
	private_data = json.loads(_user_private_key_path(username).read_text(encoding="utf-8"))
	public_data  = json.loads(_user_public_key_path(username).read_text(encoding="utf-8"))

	private_section = private_data.get("private")
	public_section  = public_data.get("public")

	if not isinstance(private_section, dict) or not isinstance(public_section, dict):
		raise ValueError("Invalid key file structure")

	public_key  = ElGamalPublicKey(
		p     = _require_int_field(public_section, "p"),
		alpha = _require_int_field(public_section, "alpha"),
		y     = _require_int_field(public_section, "y"),
	)
	private_key = ElGamalPrivateKey(x=_require_int_field(private_section, "x"))

	validate_keypair(public_key, private_key)
	return public_key, private_key


def load_public_key_only(username: str = None) -> ElGamalPublicKey:
	"""
	load only the public key from a file

	raises:
		FileNotFoundError
		ValueError: If username is not provided.
	"""
	if username is None:
		raise ValueError("username must be provided")
	
	path = _user_public_key_path(username)
	
	data = json.loads(path.read_text(encoding="utf-8"))
	public_section = data.get("public")

	if not isinstance(public_section, dict):
		raise ValueError("Invalid public key file structure")
	
	return ElGamalPublicKey(
		p	  =_require_int_field(public_section, "p"),
		alpha =_require_int_field(public_section, "alpha"),
		y	  =_require_int_field(public_section, "y"),
	)
