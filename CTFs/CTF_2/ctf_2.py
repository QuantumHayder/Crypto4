import os
from PIL import Image
import numpy as np

def reveal_secret_flag():
    """
    CTF 2 — Visual Cryptography Solver
    ----------------------------------
    This script takes two 'noise' images and overlaps them using an 
    XOR operation to produce the key.
    """
    
    file1, file2 = "Layer1.png", "Layer2.png"

   
    if not (os.path.exists(file1) and os.path.exists(file2)):
        print(f"Damn! I couldn't find {file1} or {file2} in the folder.")
        return
    
    img1 = Image.open(file1)
    img2 = Image.open(file2)

    pixels1 = np.array(img1)
    pixels2 = np.array(img2)

    print(f" Analyzing images -> (Dimensions: {pixels1.shape})")

    hidden_data = np.bitwise_xor(pixels1, pixels2)

    final_image = Image.fromarray(hidden_data)
    
    output_filename = "flag_uncovered.png"
    final_image.save(output_filename)
    final_image.show()

    print(f"\n Done! Check {output_filename} to find the secret flag.")

if __name__ == "__main__":
    reveal_secret_flag()