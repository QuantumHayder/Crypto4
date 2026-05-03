"""
CTF 2 — Image Manipulation Solver
====================================
Challenge: Two PNG images that look like random noise individually,
but together they reveal a secret.

Approach:
This is a classic Visual Cryptography / One-Time Pad challenge.
Each image is random noise on its own, but one was created by
XORing the secret image with random data, and the other IS that
random data. XORing them cancels out the noise and reveals the flag.

    Layer1 = Secret XOR Random
    Layer2 = Random
    Layer1 XOR Layer2 = Secret XOR Random XOR Random = Secret
"""

from PIL import Image
import numpy as np


def solve():
    # Load both noise images
    img1 = np.array(Image.open("Layer1.png"))
    img2 = np.array(Image.open("Layer2.png"))

    print(f"[*] Layer1: {img1.shape}")
    print(f"[*] Layer2: {img2.shape}")

    # XOR pixel-by-pixel — the noise cancels out, revealing the hidden message
    result = np.bitwise_xor(img1, img2)

    # Save the result
    output = Image.fromarray(result)
    output.save("ctf2_result.png")
    output.show()

    print("[✓] Result saved to ctf2_result.png — open it to see the flag!")


if __name__ == "__main__":
    solve()