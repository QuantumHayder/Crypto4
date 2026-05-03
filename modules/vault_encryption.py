from .encryption import AES_Encryption
from .sign import sign_vault
from .verify import verify_vault
from .elgamal import load_keypair

from pathlib import Path
import json
from enum import Enum

class Entry(Enum):
    WEBSITE = "website"
    USERNAME = "username"
    PASSWORD = "password"

class VaultEncryption:
    """ 
    Inputs: 
        • Master password 
        • Credential operations (add / retrieve / update / delete) 
    Outputs: 
        • Encrypted vault file 
        • Decrypted credentials on retrieval (the vault is decrypted in memory and the 
        selected entry is displayed to the user) 
    Functionality: 
        During vault initialization, the SHA-256 of the master password is used as the AES data 
        key. This data key is used to encrypt and decrypt the entire vault file.
    """
    
    def __init__(self, username: str,password: str):
        self.username = username
        self.password = password
        self.aes_object = AES_Encryption(password)

    def _load_vault(self):
         # 1) retrieve vault file if present
        vault_path = Path(f"vaults/{self.username}/vault.json")
        
        #2) verify vault
        pub_k, _ = load_keypair(self.username)
        if not verify_vault(vault_path, pub_k):
            raise Exception("Signature invalid — vault may be tampered.")
        
        # 2) decrypt vault using data_key
        # Then decrypt
        data = json.loads(vault_path.read_text(encoding="utf-8"))
        plain = self.aes_object.decrypt(data["encrypted_vault"])
        return json.loads(plain)["entries"]
    
    def _save_vault(self, entries):  # rename param to 'entries' for clarity
        vault_path = Path(f"vaults/{self.username}/vault.json")
        # Encrypt the INNER structure
        encrypted_vault = self.aes_object.encrypt(json.dumps({"entries": entries}))
        
        # Write the OUTER structure to disk
        vault_path.write_text(json.dumps({"encrypted_vault": encrypted_vault, "signature": {}}, indent=2))
        # Then sign
        pub_k, priv_k = load_keypair(self.username)
        sign_vault(vault_path, pub_k, priv_k)
        

    
    def add(self, website: str, username: str,password: str):
        entries  = self._load_vault()
        # 4) Modify vault file
        entries.append({
        "website": website,
        "username": username,
        "password": password
        })
        # 6) Resign vault file
        # Module 3 function -> Waiting
        return self._save_vault(entries)
    
    def retrieve(self, entry_index: int, entry: Entry):
        entries = self._load_vault()
        return entries[entry_index][entry.value]
    
    def update(self, entry_index: int, entry: Entry, value: str):
        entries = self._load_vault()
        # 4) Modify vault file
        entries[entry_index][entry.value] = value
        # 6) Resign vault file
        # Module 3 function -> Waiting
        return self._save_vault(entries)
    
    def delete(self, entry_index: int):
        entries = self._load_vault()
        # 4) Delete vault entry
        del entries[entry_index]
        # 6) Resign vault file
        # Module 3 function -> Waiting
        
        return self._save_vault(entries)