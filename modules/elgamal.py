import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from modules.config import ELGAMAL_PARAMS

DEFAULT_KEYS_DIR = Path("keys")


def _user_key_path(username: str) -> Path:
	"""Get the full key file path for a user."""
	return DEFAULT_KEYS_DIR / f"{username}_key.json"


def _user_public_key_path(username: str) -> Path:
	"""Get the public key export file path for a user."""
	return DEFAULT_KEYS_DIR / f"{username}_public.json"


@dataclass(frozen=True)
class ElGamalPublicKey:
	p: int
	g: int
	y: int


@dataclass(frozen=True)
class ElGamalPrivateKey:
	x: int


def generate_keypair(username: str):
	"""
	Generate an ElGamal keypair using shared parameters from config.
	
	Raises an error if keys already exist for this user to prevent accidental overwrite.
	
	Args:
	    username: Username (required) to associate with this keypair.
	
	Returns:
	    (ElGamalPublicKey, ElGamalPrivateKey): The public and private key pair.
	    
	Raises:
	    ValueError: If username is invalid or keys already exist for this user.
	"""
	if not username or not isinstance(username, str):
		raise ValueError("username must be a non-empty string")
	
	key_path = _user_key_path(username)
	if key_path.exists():
		raise ValueError(f"Keys already exist for user '{username}'. Use load_keypair() to load them, or delete the file and try again.")
	
	p = ELGAMAL_PARAMS["p"]
	g = ELGAMAL_PARAMS["g"]
	q = (p - 1) // 2 
	
	x = secrets.randbelow(q - 2) + 2
	
	# y = g^x mod p
	y = pow(g, x, p)
	
	return ElGamalPublicKey(p=p, g=g, y=y), ElGamalPrivateKey(x=x)


def validate_keypair(public_key: ElGamalPublicKey, private_key: ElGamalPrivateKey) -> None:
	"""
	Validate that a keypair is mathematically consistent.
	
	Raises:
	    ValueError: If any validation check fails.
	"""
	if public_key.p <= 2:
		raise ValueError("Invalid prime modulus")
	if public_key.g <= 1 or public_key.g >= public_key.p:
		raise ValueError("Invalid generator")
	if public_key.y <= 1 or public_key.y >= public_key.p:
		raise ValueError("Invalid public key value")
	if private_key.x <= 1 or private_key.x >= public_key.p - 1:
		raise ValueError("Invalid private key value")
	if pow(public_key.g, private_key.x, public_key.p) != public_key.y:
		raise ValueError("Public and private key values do not match")


def save_keypair(
	public_key: ElGamalPublicKey,
	private_key: ElGamalPrivateKey,
	username: str,
	file_path: str | Path = None,
) -> Path:
	"""
	Save keypair to JSON file (both public and private).
	
	Args:
	    public_key: The ElGamal public key.
	    private_key: The ElGamal private key.
	    username: Username (required) to save keypair for.
	    file_path: Custom file path (optional, overrides username-based path).
	    
	Returns:
	    Path: The path where the keypair was saved.
	"""
	if not username or not isinstance(username, str):
		raise ValueError("username must be a non-empty string")
	
	validate_keypair(public_key, private_key)
	
	if file_path is None:
		path = _user_key_path(username)
	else:
		path = Path(file_path)
	
	path.parent.mkdir(parents=True, exist_ok=True)

	payload = {
		"public": {
			"p": str(public_key.p),
			"g": str(public_key.g),
			"y": str(public_key.y),
		},
		"private": {
			"x": str(private_key.x),
		},
	}

	path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
	return path


def _require_int_field(section: dict, name: str) -> int:
	"""Extract an integer field from JSON section with validation."""
	value = section.get(name)
	if value is None:
		raise ValueError(f"Missing field: {name}")
	try:
		return int(value)
	except (TypeError, ValueError) as exc:
		raise ValueError(f"Invalid integer field: {name}") from exc


def load_keypair(username: str, file_path: str | Path = None):
	"""
	Load keypair from JSON file and validate it.
	
	Args:
	    username: Username (required) to load keys for.
	    file_path: Custom file path (optional, overrides username-based path).
	    
	Returns:
	    (ElGamalPublicKey, ElGamalPrivateKey): The loaded keypair.
	    
	Raises:
	    FileNotFoundError: If the key file does not exist.
	    ValueError: If the key file is invalid or keys don't match.
	"""
	if not username or not isinstance(username, str):
		raise ValueError("username must be a non-empty string")
	
	if file_path is None:
		path = _user_key_path(username)
	else:
		path = Path(file_path)
	
	data = json.loads(path.read_text(encoding="utf-8"))

	public_section = data.get("public")
	private_section = data.get("private")
	if not isinstance(public_section, dict) or not isinstance(private_section, dict):
		raise ValueError("Invalid key file structure")

	public_key = ElGamalPublicKey(
		p=_require_int_field(public_section, "p"),
		g=_require_int_field(public_section, "g"),
		y=_require_int_field(public_section, "y"),
	)
	private_key = ElGamalPrivateKey(x=_require_int_field(private_section, "x"))
	validate_keypair(public_key, private_key)
	return public_key, private_key


def export_public_key(username: str, output_path: str | Path = None) -> Path:
	"""
	Export only the public key for sharing with other users.
	
	Args:
	    username: Username whose public key to export.
	    output_path: Where to save the public key (default: keys/{username}_public.json).
	    
	Returns:
	    Path: The path where the public key was saved.
	    
	Raises:
	    FileNotFoundError: If the user's keypair does not exist.
	"""
	public_key, _ = load_keypair(username=username)
	
	if output_path is None:
		path = _user_public_key_path(username)
	else:
		path = Path(output_path)
	
	path.parent.mkdir(parents=True, exist_ok=True)
	
	payload = {
		"public": {
			"p": str(public_key.p),
			"g": str(public_key.g),
			"y": str(public_key.y),
		}
	}
	
	path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
	return path


def load_public_key_only(username: str = None, file_path: str | Path = None) -> ElGamalPublicKey:
	"""
	Load only the public key from a file (for verification by others).
	
	Args:
	    username: Username whose public key to load (uses default path if file_path not provided).
	    file_path: Custom file path to public key file (if provided, username is ignored).
	    
	Returns:
	    ElGamalPublicKey: The public key.
	    
	Raises:
	    FileNotFoundError: If the public key file does not exist.
	    ValueError: If neither username nor file_path is provided.
	"""
	if file_path is None and username is None:
		raise ValueError("Either username or file_path must be provided")
	
	if file_path is None:
		path = _user_public_key_path(username)
	else:
		path = Path(file_path)
	
	data = json.loads(path.read_text(encoding="utf-8"))
	public_section = data.get("public")
	
	if not isinstance(public_section, dict):
		raise ValueError("Invalid public key file structure")
	
	return ElGamalPublicKey(
		p=_require_int_field(public_section, "p"),
		g=_require_int_field(public_section, "g"),
		y=_require_int_field(public_section, "y"),
	)
