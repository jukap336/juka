import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Derivación de la clave a partir de la contraseña
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Función para cifrar usando AES GCM
def encrypt_file(password: str):
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            salt = os.urandom(16)
            key = derive_key(password, salt)
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            with open(file_path, 'rb') as f:
                data = f.read()

            ciphertext = encryptor.update(data) + encryptor.finalize()
            encrypted_data = urlsafe_b64encode(salt + iv + encryptor.tag + ciphertext)

            save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(encrypted_data)
                messagebox.showinfo("Éxito", f"Archivo cifrado guardado en: {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo cifrar el archivo: {e}")

# Función para descifrar usando AES GCM
def decrypt_file(password: str):
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            decoded_data = urlsafe_b64decode(encrypted_data)
            salt = decoded_data[:16]
            iv = decoded_data[16:28]
            tag = decoded_data[28:44]
            ciphertext = decoded_data[44:]
            key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            save_path = filedialog.asksaveasfilename(defaultextension=".dec", filetypes=[("Decrypted Files", "*.dec")])
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(decrypted_data)
                messagebox.showinfo("Éxito", f"Archivo descifrado guardado en: {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo descifrar el archivo: {e}")

# Configuración de la interfaz de Daschript
def main():
    ventana = tk.Tk()
    ventana.title("Daschript - Cifrado y Descifrado de Archivos")
    ventana.geometry("400x200")

    # Etiqueta y entrada para la contraseña
    tk.Label(ventana, text="Contraseña:", font=("Arial", 12)).pack(pady=10)
    entry_password = tk.Entry(ventana, show='*', width=40)
    entry_password.pack(pady=5)

    # Botones para cifrar y descifrar
    btn_cifrar = tk.Button(
        ventana,
        text="Cifrar Archivo",
        command=lambda: encrypt_file(entry_password.get())
    )
    btn_cifrar.pack(pady=10)

    btn_descifrar = tk.Button(
        ventana,
        text="Descifrar Archivo",
        command=lambda: decrypt_file(entry_password.get())
    )
    btn_descifrar.pack(pady=10)

    ventana.mainloop()

if __name__ == "__main__":
    main()

