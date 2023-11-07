import tkinter as tk
from tkinter import filedialog
import hashlib
import base64
import os

# Function to generate a random key and save it to a text file
def generate_random_key_and_save():
    key = generate_random_key()
    key_file_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Save encryption key to a text file")
    if key_file_path:
        with open(key_file_path, 'wb') as key_file:
            key_file.write(key)
        status_label.config(text=f"Encryption key saved to '{key_file_path}'")

# Function to generate a random key
def generate_random_key():
    return os.urandom(16)

# Function to perform encryption
def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Encrypt using XOR
    xor_encrypted_data = bytearray(plaintext[i] ^ key[i % len(key)] for i in range(len(plaintext)))

    # Encode in Base64
    base64_encoded_data = base64.b64encode(xor_encrypted_data)

    # Write to the output file
    with open(output_file, 'wb') as f:
        f.write(base64_encoded_data)

# Function to perform decryption
def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        base64_encoded_data = f.read()

    # Decode from Base64
    xor_encrypted_data = base64.b64decode(base64_encoded_data)

    # Decrypt using XOR
    decrypted_data = bytearray(xor_encrypted_data[i] ^ key[i % len(key)] for i in range(len(xor_encrypted_data)))

    # Write to the output file
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

# Function to handle the "Encrypt" button click
def encrypt_button_click():
    input_file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if input_file_path:
        output_file_path = filedialog.asksaveasfilename(defaultextension=".bin", title="Save encrypted file")
        if output_file_path:
            key_file_path = filedialog.askopenfilename(title="Select the encryption key")
            if key_file_path:
                with open(key_file_path, 'rb') as key_file:
                    key = key_file.read()
                    encrypt_file(input_file_path, output_file_path, key)
                    status_label.config(text=f"File '{input_file_path}' encrypted to '{output_file_path}'")

# Function to handle the "Decrypt" button click
def decrypt_button_click():
    input_file_path = filedialog.askopenfilename(title="Select a file to decrypt")
    if input_file_path:
        key_file_path = filedialog.askopenfilename(title="Select the decryption key")
        if key_file_path:
            with open(key_file_path, 'rb') as key_file:
                key = key_file.read()
                output_file_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Save decrypted file")
                if output_file_path:
                    decrypt_file(input_file_path, output_file_path, key)
                    status_label.config(text=f"File '{input_file_path}' decrypted to '{output_file_path}'")

# Create the main application window
app = tk.Tk()
app.title("Encryption and Decryption")

# Create and configure widgets
encrypt_button = tk.Button(app, text="Encrypt", command=encrypt_button_click)
decrypt_button = tk.Button(app, text="Decrypt", command=decrypt_button_click)
generate_key_button = tk.Button(app, text="Generate and Save Encryption Key", command=generate_random_key_and_save)
status_label = tk.Label(app, text="", pady=10)

# Pack widgets
generate_key_button.pack()
encrypt_button.pack()
decrypt_button.pack()
status_label.pack()

# Start the GUI main loop
app.mainloop()

