with open("CTFs/CTF_3/shifted.txt", "r") as f:
    text = f.read()

parts = text.split()
numbers = list(map(int, parts))

flag = ""
for n in numbers:
    shifted = n >> 1
    character = chr(shifted)
    flag += character

print("Flag:", flag)