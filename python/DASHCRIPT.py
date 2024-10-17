import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def derive_key(password: str, salt: bytes) -> bytes:
    """Deriva una clave criptográfica a partir de una contraseña utilizando PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_aes_gcm(message: str, password: str) -> str:
    """Cifra un mensaje utilizando AES en modo GCM."""
    salt = os.urandom(16)
    iv = os.urandom(12)  # GCM mode recomienda un IV de 12 bytes
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    tag = encryptor.tag

    # Concatenar salt, iv, tag y ciphertext
    return urlsafe_b64encode(salt + iv + tag + ciphertext).decode('utf-8')

def decrypt_aes_gcm(encrypted_message: str, password: str) -> str:
    """Descifra un mensaje cifrado con AES en modo GCM utilizando una contraseña."""
    decoded_data = urlsafe_b64decode(encrypted_message)
    salt = decoded_data[:16]
    iv = decoded_data[16:28]
    tag = decoded_data[28:44]
    ciphertext = decoded_data[44:]
    
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

def copy_to_clipboard(text):
    """Copia el texto al portapapeles."""
    root.clipboard_clear()  # Limpia el portapapeles
    root.clipboard_append(text)  # Añade el nuevo texto al portapapeles
    root.update()  # Actualiza el portapapeles

def process_encryption():
    message = entry_message.get()
    password = entry_password.get()
    
    if not message or not password:
        messagebox.showwarning("Advertencia", "Por favor, ingresa un mensaje y una contraseña.")
        return
    
    try:
        encrypted_message = encrypt_aes_gcm(message, password)
        messagebox.showinfo("Mensaje cifrado", encrypted_message)
        copy_to_clipboard(encrypted_message)  # Copia el mensaje cifrado al portapapeles
        messagebox.showinfo("Copiado", "El mensaje cifrado ha sido copiado al portapapeles.")
    except Exception as e:
        messagebox.showerror("Error", f"Error al cifrar el mensaje: {str(e)}")

def process_decryption():
    encrypted_message = entry_message.get()
    password = entry_password.get()

    if not encrypted_message or not password:
        messagebox.showwarning("Advertencia", "Por favor, ingresa un mensaje cifrado y una contraseña.")
        return
    
    try:
        decrypted_message = decrypt_aes_gcm(encrypted_message, password)
        messagebox.showinfo("Mensaje descifrado", decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", f"Error al descifrar el mensaje: {str(e)}")

# Configuración de la interfaz gráfica
root = tk.Tk()
root.title("DASHCRIPT A TU SERVICIO")
root.geometry("500x400")
root.configure(bg='black')  # Cambiar el fondo a negro

# Etiquetas y entradas para el mensaje y la contraseña
label_title = tk.Label(root, text="DASHCRIPT A TU SERVICIO", bg='black', fg='white', font=("Arial", 16))
label_title.pack(pady=10)

label_message = tk.Label(root, text="Mensaje a cifrar/descifrar:", bg='black', fg='white')
label_message.pack(pady=5)
entry_message = tk.Entry(root, width=50)
entry_message.pack(pady=5)

label_password = tk.Label(root, text="Contraseña:", bg='black', fg='white')
label_password.pack(pady=5)
entry_password = tk.Entry(root, width=50, show="*")
entry_password.pack(pady=5)

# Botones para cifrar y descifrar el mensaje
button_encrypt = tk.Button(root, text="Cifrar y copiar", command=process_encryption, bg='gray', fg='black')
button_encrypt.pack(pady=10)

button_decrypt = tk.Button(root, text="Descifrar", command=process_decryption, bg='gray', fg='black')
button_decrypt.pack(pady=10)

# Ejecuta la aplicación
root.mainloop()



