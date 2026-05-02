from PIL import Image
import os

img = Image.open("stego.png").convert("L")

pixels = list(img.getdata())

bits = ""

for pixel in pixels:
    bits += str(pixel & 1)

chars = [bits[i:i+8] for i in range(0, len(bits), 8)]

result = ""

for c in chars:
    val = int(c, 2)

    if val == 0:
        break

    if 32 <= val <= 126:
        result += chr(val)

print(f"Extracted message: {result}")

output_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "result.txt"
)

with open(output_path, "w") as f:
    f.write(result)