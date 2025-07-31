import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import hashlib
import os
import json
import time
import shutil

def get_shared_key():
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake'
    ).derive(b"shared_secret_example")

def encrypt_file():
    filepath = filedialog.askopenfilename(title="Select File to Encrypt")
    if not filepath:
        return

    progress.start()
    root.after(100, lambda: finish_encryption(filepath))

def finish_encryption(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        key = get_shared_key()
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(key)
        encrypted = cipher.encrypt(nonce, data, None)

        original_name = os.path.basename(filepath)
        timestamp = int(time.time())
        output_name = f"encrypted_{original_name}_{timestamp}.bin"

        with open(output_name, "wb") as f:
            f.write(nonce + encrypted)

        cloud_dir = "cloud_storage"
        os.makedirs(cloud_dir, exist_ok=True)
        shutil.copy(output_name, os.path.join(cloud_dir, output_name))

        file_hash = hashlib.sha256(data).hexdigest()
        block = {
            "index": timestamp,
            "data_hash": file_hash,
            "original_file": original_name,
            "encrypted_file": output_name
        }

        blockchain = []
        if os.path.exists("blockchain.json"):
            try:
                with open("blockchain.json", "r") as f:
                    blockchain = json.load(f)
            except json.JSONDecodeError:
                blockchain = []

        blockchain.append(block)
        with open("blockchain.json", "w") as f:
            json.dump(blockchain, f, indent=4)

        messagebox.showinfo("Success", f"File encrypted and uploaded to simulated cloud:\n{output_name}")
    finally:
        progress.stop()

def decrypt_file():
    enc_file = filedialog.askopenfilename(
        title="Select Encrypted File from Cloud",
        initialdir="cloud_storage",
        filetypes=[("Encrypted Files", "*.bin")]
    )
    if not enc_file:
        return

    progress.start()
    root.after(100, lambda: finish_decryption(enc_file))

def finish_decryption(enc_file):
    try:
        if not os.path.exists("blockchain.json"):
            messagebox.showerror("Error", "Blockchain file not found.")
            return

        with open(enc_file, "rb") as f:
            content = f.read()

        nonce = content[:12]
        ciphertext = content[12:]
        key = get_shared_key()

        cipher = ChaCha20Poly1305(key)
        try:
            decrypted = cipher.decrypt(nonce, ciphertext, None)
        except Exception:
            messagebox.showerror("Error", "Decryption failed. Wrong key or corrupted file.")
            return

        with open("decrypted_output.txt", "wb") as f:
            f.write(decrypted)

        actual_hash = hashlib.sha256(decrypted).hexdigest()

        try:
            with open("blockchain.json", "r") as f:
                chain = json.load(f)
        except json.JSONDecodeError:
            chain = []

        match_found = any(block["data_hash"] == actual_hash for block in chain)

        if match_found:
            messagebox.showinfo("Success", "Decryption successful and integrity verified.")
        else:
            messagebox.showwarning("Warning", "Decrypted, but hash not found in blockchain.")
    finally:
        progress.stop()

# GUI setup
root = tk.Tk()
root.title("Secure Cloud File Storage (Hybrid Encryption)")
root.geometry("460x300")

title = tk.Label(root, text="Hybrid Crypto File Encryptor (ChaCha20 + ECC)", font=("Arial", 12, "bold"))
title.pack(pady=10)

btn_encrypt = tk.Button(root, text="Encrypt File (Upload to Cloud)", command=encrypt_file, width=40)
btn_encrypt.pack(pady=6)

btn_decrypt = tk.Button(root, text="Decrypt File from Cloud & Verify", command=decrypt_file, width=40)
btn_decrypt.pack(pady=6)

# Progress bar
progress = ttk.Progressbar(root, orient="horizontal", mode="indeterminate", length=300)
progress.pack(pady=20)

footer = tk.Label(root, text="Created by Tenzin", font=("Arial", 9), fg="gray")
footer.pack(side="bottom", pady=10)

root.mainloop()