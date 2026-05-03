import requests

ORACLE = "http://cbc-ctf.westeurope.azurecontainer.io:5000/oracle"
CT_HEX = "b248f0e8f4e3548b995d2215f54b72bd5d3b211b522b7a5ea25c5763e7425447e440e4d85933807e1385d11cd1959975"
BS = 16


def padding_ok(hex_str):
    try:
        r = requests.post(ORACLE, json={"ciphertext_hex": hex_str}, timeout=5)
        return r.json().get("valid_padding") == True
    except:
        return False


def main():
    ct = bytes.fromhex(CT_HEX)
    blocks = [ct[i:i+BS] for i in range(0, len(ct), BS)]
    result = ""

    for b in range(len(blocks) - 1):
        print(f"\nblock {b+1}:")
        prev, target = blocks[b], blocks[b+1]
        intermediate = [0] * BS
        plaintext = [0] * BS

        for i in range(BS - 1, -1, -1):
            pad = BS - i
            fake = bytearray(prev)
            for k in range(i + 1, BS):
                fake[k] = intermediate[k] ^ pad

            for guess in range(256):
                fake[i] = guess
                if not padding_ok((bytes(fake) + target).hex()):
                    continue
                if i == BS - 1:
                    check = bytearray(fake)
                    check[i-1] ^= 1
                    if not padding_ok((bytes(check) + target).hex()):
                        continue
                intermediate[i] = guess ^ pad
                plaintext[i] = intermediate[i] ^ prev[i]
                val = plaintext[i]
                char = chr(val) if 32 <= val <= 126 else "?"
                print(char)
                break
            else:
                raise Exception(f"stuck on byte {i}")

        result += "".join(chr(b) if 32 <= b <= 126 else "?" for b in plaintext)

    print(f"\nresult: {result}")


if __name__ == "__main__":
    main()