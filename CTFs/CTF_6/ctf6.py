from sympy import factorint

data = {}
with open("CTFs/CTF_6/challenge.txt", 'r') as f:
    next(f)
    for line in f:
        if '=' in line and any(var in line for var in ['n', 'e', 'ciphertext']):
            parts = line.split('=', 1)
            key = parts[0].strip()
            val = parts[1].strip()
            data[key] = int(val)

    n = data['n']
    e = data['e']
    ct = data['ciphertext']

factors = factorint(n)
p, q = list(factors.keys())

phi = (p - 1) * (q - 1)
d   = pow(e, -1, phi)

m   = pow(ct, d, n)
flag = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
print("Flag:", flag)