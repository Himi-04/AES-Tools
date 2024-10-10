import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

# Function to derive a key from a password
def derive_key(password):
    salt = os.urandom(16)  # Use a random salt for security
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES key length of 32 bytes
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

# Function to encrypt the image
def encrypt_image(image_path, password, save_path):
    with open(image_path, 'rb') as file:
        original_image = file.read()

    key, salt = derive_key(password)
    
    # Initialization vector for AES
    iv = os.urandom(16)  # AES block size is 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_image = iv + salt + encryptor.update(original_image) + encryptor.finalize()

    with open(save_path, 'wb') as file:
        file.write(encrypted_image)

    return save_path

# Function to decrypt the image
def decrypt_image(encrypted_image_path, password, save_path):
    with open(encrypted_image_path, 'rb') as file:
        encrypted_image = file.read()

    iv = encrypted_image[:16]  # Extract the IV
    salt = encrypted_image[16:32]  # Extract the salt
    ciphertext = encrypted_image[32:]  # The rest is the actual encrypted data

    # Derive the key using the extracted salt
    key = derive_key_from_salt(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_image = decryptor.update(ciphertext) + decryptor.finalize()

    with open(save_path, 'wb') as file:
        file.write(decrypted_image)

    return save_path

def derive_key_from_salt(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES key length of 32 bytes
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to show/hide fields based on selection
def show_fields(option):
    if option == "Encrypt":
        encrypt_frame.pack(fill=tk.BOTH, expand=True)
        decrypt_frame.pack_forget()
    elif option == "Decrypt":
        decrypt_frame.pack(fill=tk.BOTH, expand=True)
        encrypt_frame.pack_forget()

# UI Functions
def select_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg;*.jpeg;*.png")])
    if file_path:
        image_path_var.set(file_path)

def save_encrypted_image():
    format_choice = messagebox.askquestion("Choose Format", "Do you want to save as PNG?", icon='question')
    extension = ".png" if format_choice == 'yes' else ".jpg"
    
    save_path = filedialog.asksaveasfilename(defaultextension=extension, filetypes=[("Image Files", "*.png;*.jpg")])
    if save_path:
        save_encrypted_path_var.set(save_path)

def save_decrypted_image():
    save_path = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("Image Files", "*.jpg;*.jpeg;*.png")])
    if save_path:
        save_decrypted_path_var.set(save_path)

def encode_image():
    image_path = image_path_var.get()
    password = password_var.get()
    save_path = save_encrypted_path_var.get()

    if not image_path or not password or not save_path:
        messagebox.showerror("Error", "Please select an image, enter a password, and specify a save location.")
        return

    encrypted_image_path = encrypt_image(image_path, password, save_path)
    messagebox.showinfo("Success", f"Image encrypted and saved as {encrypted_image_path}")

def decode_image():
    encrypted_image_path = image_path_var.get()
    password = password_var.get()
    save_path = save_decrypted_path_var.get()

    if not encrypted_image_path or not password or not save_path:
        messagebox.showerror("Error", "Please select an encrypted image, enter a password, and specify a save location.")
        return

    decrypted_image_path = decrypt_image(encrypted_image_path, password, save_path)
    messagebox.showinfo("Success", f"Image decrypted and saved as {decrypted_image_path}")

# GUI Setup
root = tk.Tk()
root.title("Image Encryptor/Decryptor")

# Option selection
option_var = tk.StringVar(value="Encrypt")

tk.Label(root, text="Select Operation:").pack(pady=5)
tk.Radiobutton(root, text="Encrypt", variable=option_var, value="Encrypt", command=lambda: show_fields("Encrypt")).pack(anchor=tk.W)
tk.Radiobutton(root, text="Decrypt", variable=option_var, value="Decrypt", command=lambda: show_fields("Decrypt")).pack(anchor=tk.W)

# Frames for Encrypt and Decrypt
encrypt_frame = tk.Frame(root)
decrypt_frame = tk.Frame(root)

# Encrypt Frame
image_path_var = tk.StringVar()
password_var = tk.StringVar()
save_encrypted_path_var = tk.StringVar()

tk.Label(encrypt_frame, text="Image Path:").grid(row=0, column=0, padx=5, pady=5)
tk.Entry(encrypt_frame, textvariable=image_path_var, width=40).grid(row=0, column=1, padx=5, pady=5)
tk.Button(encrypt_frame, text="Browse", command=select_image).grid(row=0, column=2, padx=5, pady=5)

tk.Label(encrypt_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
tk.Entry(encrypt_frame, textvariable=password_var, show='*').grid(row=1, column=1, padx=5, pady=5)

tk.Label(encrypt_frame, text="Save Encrypted Path:").grid(row=2, column=0, padx=5, pady=5)
tk.Entry(encrypt_frame, textvariable=save_encrypted_path_var, width=40).grid(row=2, column=1, padx=5, pady=5)
tk.Button(encrypt_frame, text="Save Encrypted As", command=save_encrypted_image).grid(row=2, column=2, padx=5, pady=5)

tk.Button(encrypt_frame, text="Encode Image", command=encode_image).grid(row=3, column=1, padx=5, pady=5)

# Decrypt Frame
decrypt_frame = tk.Frame(root)

save_decrypted_path_var = tk.StringVar()

tk.Label(decrypt_frame, text="Encrypted Image Path:").grid(row=0, column=0, padx=5, pady=5)
tk.Entry(decrypt_frame, textvariable=image_path_var, width=40).grid(row=0, column=1, padx=5, pady=5)
tk.Button(decrypt_frame, text="Browse", command=select_image).grid(row=0, column=2, padx=5, pady=5)

tk.Label(decrypt_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
tk.Entry(decrypt_frame, textvariable=password_var, show='*').grid(row=1, column=1, padx=5, pady=5)

tk.Label(decrypt_frame, text="Save Decrypted Path:").grid(row=2, column=0, padx=5, pady=5)
tk.Entry(decrypt_frame, textvariable=save_decrypted_path_var, width=40).grid(row=2, column=1, padx=5, pady=5)
tk.Button(decrypt_frame, text="Save Decrypted As", command=save_decrypted_image).grid(row=2, column=2, padx=5, pady=5)

tk.Button(decrypt_frame, text="Decode Image", command=decode_image).grid(row=3, column=1, padx=5, pady=5)

# Show encrypt fields by default
show_fields("Encrypt")

root.mainloop()
