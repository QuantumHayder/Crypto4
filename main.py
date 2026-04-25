from modules.hash import hash_file, verify_integrity
from modules.encryption import aes_ed, rsa_ed
from modules.password import check_strength, hash_pw, verify_pw
from modules.elgamal import describe_keypair, generate_keypair, load_keypair, save_keypair, export_public_key, load_public_key_only
from getpass import getpass
def menu():
    print("\nSelect operation: ")
    print("1. hash file")
    print("2. Check file integrity")
    print("3. AES Encrypt/Decrypt")
    print("4. RSA Encrypt/Decrypt")
    print("5. Password Manager")
    print("6. ElGamal Key Management")
    print("0. Exit")
    
print("""
      Initializing Crypto4 v0.0...
      
      \nWelcome, Agent! Yur mission, should you choose to accept it:
      -Analyze and hash files to detect tampering
      -Encrypt and decrypt messages with AES and RSA
      -Securely manage passwords and assess their strength
      
      All systems online. Data protection protocols active.
      Prepare to enter the world of digital secrecy!
      """)

while True:
    menu()
    choice = input("Enter choice(0-6): ")
    if choice == "0":
        break
    
    elif choice == "1":
        file_path = input("Enter file path: ")
        print("\nSHA Hash of the file is: ", hash_file(file_path))
        
    elif choice == "2":
        file_path1 = input("Enter file1 path: ")
        file_path2 = input("Enter file2 path: ")
        print(verify_integrity(file_path1, file_path2))
        
    elif choice == "3":
        message = input("Enter your message: ")
        key, ciphertext, plaintext = aes_ed(message)
        print("AES Key: ", key)
        print("AES Ciphertext: ", ciphertext)
        print("AES Plaintext: ", plaintext)
        
    elif choice == "4":
        message = input("Enter your message: ")
        ciphertext, plaintext = rsa_ed(message)
        print("RSA Ciphertext encrypted with a public key: ", ciphertext)
        print("RSA Plaintext decrypted with a private key: ", plaintext)
        
    elif choice == "5":
        while True:
            password1 = getpass("Enter a password to check strength: ")
            print(check_strength(password1))
            if check_strength(password1).startswith("Weak"):
                print("Please choose a stronger password")
            else:
                break
        hashed_password = hash_pw(password1)
        print("Hashed password: ", hashed_password)
        attempt = getpass("re-enter the password to verify: ")
        print(verify_pw(attempt, hashed_password))
    elif choice == "6":
        username = input("Enter username: ").strip()
        action = input("Type 'g' to generate, 'l' to load, 'e' to export public key: ").strip().lower()
        
        if action == "g":
            public_key, private_key = generate_keypair(username)
            saved_path = save_keypair(public_key, private_key, username=username)
            print(f"✓ ElGamal keypair saved to {saved_path}")
            print(describe_keypair(public_key))
            
        elif action == "l":
            try:
                public_key, _ = load_keypair(username=username)
                print(describe_keypair(public_key))
            except FileNotFoundError:
                print(f"✗ No keypair found for user '{username}'")
                
        elif action == "e":
            try:
                export_path = export_public_key(username)
                print(f"✓ Public key exported to {export_path}")
            except FileNotFoundError:
                print(f"✗ No keypair found for user '{username}'")
                
        else:
            print("✗ Invalid ElGamal action")
    else:
        print("Invalid choice")
        
print("Agent, you are exiting your Crypto4 mission, stay strong and secure")