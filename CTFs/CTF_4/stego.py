from PIL import Image
import os

img = Image.open("stego.png").convert("L")
pixels = list(img.getdata())

bits = "".join(str(p & 1) for p in pixels)

result = ""
for i in range(0, len(bits), 8):
    val = int(bits[i:i+8], 2)
    if val == 0:
        break
    if 32 <= val <= 126:
        result += chr(val)

print(result)

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "result.txt")
with open(out, "w") as f:
    f.write(result)