import requests

ORACLE_URL = "http://cbc-ctf.westeurope.azurecontainer.io:5000/oracle"

# Exact string as provided
TARGET_CIPHERTEXT = "b248f0e8f4e3548b995d2215f54b72bd5d3b211b522b7a5ea25c5763e7425447e440e4d85933807e1385d11cd1959975"


def is_padding_valid(hex_str):
    try:
        r = requests.post(
            ORACLE_URL,
            json={"ciphertext_hex": hex_str},
            timeout=5
        )
        return r.json().get("valid_padding") == True
    except Exception:
        return False


def crack():
    ct = bytes.fromhex(TARGET_CIPHERTEXT)

    BS = 16
    blocks = [ct[i:i + BS] for i in range(0, len(ct), BS)]

    decrypted_full = ""

    for b_idx in range(len(blocks) - 1):

        print(f"\n--- Decrypting Block {b_idx + 1} ---")

        prev_block = blocks[b_idx]
        target_block = blocks[b_idx + 1]

        intermediate = [0] * BS
        plaintext_block = [0] * BS

        for byte_idx in range(BS - 1, -1, -1):

            expected_pad = BS - byte_idx
            found = False

            for guess in range(256):

                fake_prev = bytearray(prev_block)

                fake_prev[byte_idx] = guess

                for k in range(byte_idx + 1, BS):
                    fake_prev[k] = intermediate[k] ^ expected_pad

                test_hex = (bytes(fake_prev) + target_block).hex()

                if is_padding_valid(test_hex):

                    if byte_idx == BS - 1:

                        check_block = bytearray(fake_prev)
                        check_block[byte_idx - 1] ^= 1

                        check_hex = (
                            bytes(check_block) + target_block
                        ).hex()

                        if not is_padding_valid(check_hex):
                            continue

                    intermediate[byte_idx] = guess ^ expected_pad

                    plaintext_block[byte_idx] = (
                        intermediate[byte_idx]
                        ^ prev_block[byte_idx]
                    )

                    val = plaintext_block[byte_idx]

                    char = (
                        chr(val)
                        if 32 <= val <= 126
                        else "?"
                    )

                    print(
                        f"  [+] Byte {byte_idx:02d}: "
                        f"Found {hex(val)} ('{char}')"
                    )

                    found = True
                    break

            if not found:
                raise Exception(
                    f"Failed to recover byte {byte_idx}"
                )

        decrypted_full += "".join(
            chr(b) if 32 <= b <= 126 else "?"
            for b in plaintext_block
        )

    print(f"\n[***] RECOVERED SECRET: {decrypted_full}")


if __name__ == "__main__":
    crack()