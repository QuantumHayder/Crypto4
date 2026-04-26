import hashlib

# text = "Hello world!"
# hash_object = hashlib.sha256(text.encode())
# hash_digest = hash_object.hexdigest()
# print("SHA Hash of ", text, " is ", hash_digest)
def hash_password(password: str):
    hash_object = hashlib.sha256(password.encode())
    hash_digest = hash_object.hexdigest()
    return hash_digest

def hash_file(file_path):
    h = hashlib.new('sha256')
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024)
            if chunk == b"":
                break
            h.update(chunk)
    return h.hexdigest()

def verify_integrity(file1, file2):
    hash1 = hash_file(file1)
    hash2 = hash_file(file2)
    print("\nChecking integrity between ", file1, " and ", file2)
    if hash1 == hash2:
        return "file is intact. No modifications have been made"
    return "file has been probably unsafely modified"
if __name__ == "__main__":
    print("SHA Hash of file is: ", hash_file("sample.txt"))
    print(verify_integrity("dollar-circle.svg", "dollar-circle2.svg"))
    print(verify_integrity("dollar-circle.svg", "dollar-circle-modified.svg"))