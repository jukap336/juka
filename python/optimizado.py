import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_aes_gcm(message, password):
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return urlsafe_b64encode(salt + iv + encryptor.tag + ciphertext).decode()

def decrypt_aes_gcm(encrypted_message, password):
    decoded_data = urlsafe_b64decode(encrypted_message)
    salt, iv, tag, ciphertext = decoded_data[:16], decoded_data[16:28], decoded_data[28:44], decoded_data[44:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

def process_encryption():
    message, password = entry_message.get(), entry_password.get()
    if message and password:
        try:
            encrypted_message = encrypt_aes_gcm(message, password)
            messagebox.showinfo("Mensaje cifrado", encrypted_message)
            root.clipboard_clear()
            root.clipboard_append(encrypted_message)
            messagebox.showinfo("Copiado", "Mensaje copiado al portapapeles.")
        except Exception as e:
            messagebox.showerror("Error", f"Error al cifrar: {e}")
    else:
        messagebox.showwarning("Advertencia", "Faltan datos.")

def process_decryption():
    encrypted_message, password = entry_message.get(), entry_password.get()
    if encrypted_message and password:
        try:
            decrypted_message = decrypt_aes_gcm(encrypted_message, password)
            messagebox.showinfo("Mensaje descifrado", decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", f"Error al descifrar: {e}")
    else:
        messagebox.showwarning("Advertencia", "Faltan datos.")

root = tk.Tk()
root.title("DASHCRIPT")
root.geometry("500x400")
root.configure(bg='black')
root.resizable(False, False)
tk.Label(root, text="DASHCRIPT", bg='black', fg='white', font=("Arial", 16)).pack(pady=10)
tk.Label(root, text="Mensaje:", bg='black', fg='white').pack(pady=5)
entry_message = tk.Entry(root, width=50)
entry_message.pack(pady=5)
tk.Label(root, text="Contraseña:", bg='black', fg='white').pack(pady=5)
entry_password = tk.Entry(root, width=50, show="*")
entry_password.pack(pady=5)
tk.Button(root, text="Cifrar y copiar", command=process_encryption, bg='gray').pack(pady=10)
tk.Button(root, text="Descifrar", command=process_decryption, bg='gray').pack(pady=10)


root.mainloop()