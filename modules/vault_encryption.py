from encryption import AES_Encryption

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
    
    def __init__(self, password: str):
        self.password = password
        self.aes_object = AES_Encryption(password)

    def _load_vault(self, vault_path: str = '/Crypto4/vault'):
         # 1) retrieve vault file
        with open(vault_path, "r") as file:
            vault = file.read()
        # 2) decrypt vault using data_key
        try:
            plain_vault = self.aes_object.decrypt(vault)
        except ValueError:
            raise Exception("Wrong password — vault authentication failed")
        
        return json.loads(plain_vault)
    
    def _save_vault(self, vault_dict, vault_path="/Crypto4/vault"):
        vault = self.aes_object.encrypt(json.dumps(vault_dict))
        with open(vault_path, "w", encoding="utf-8") as f:
            f.write(vault)
        return vault
    
    def add(self, website: str, username: str, password: str):
        vault_dict = self._load_vault()
        # 4) Modify vault file
        vault_dict["entries"].append({
            "website": website,
            "username": username,
            "password": password
        })
        # 6) Resign vault file
        # Module 3 function -> Waiting
        return self._save_vault(vault_dict)
    
    def retrieve(self, entry_index: int, entry: Entry):
        vault_dict = self._load_vault()
        return vault_dict["entries"][entry_index][entry.value]
    
    def update(self, entry_index: int, entry: Entry, value: str):
        vault_dict = self._load_vault()
        # 4) Modify vault file
        vault_dict["entries"][entry_index][entry.value] = value
        # 6) Resign vault file
        # Module 3 function -> Waiting
        return self._save_vault(vault_dict)
    
    def delete(self, entry_index: int):
        vault_dict = self._load_vault()
        # 4) Delete vault entry
        del vault_dict["entries"][entry_index]
        # 6) Resign vault file
        # Module 3 function -> Waiting
        
        return self._save_vault(vault_dict)