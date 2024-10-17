import os
import random
import string
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Variable para almacenar intentos fallidos
intentos_fallidos = 0

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
def encrypt_aes_gcm(message: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return urlsafe_b64encode(salt + iv + encryptor.tag + ciphertext)

# Función para descifrar usando AES GCM
def decrypt_aes_gcm(encrypted_message: bytes, password: str) -> bytes:
    decoded_data = urlsafe_b64decode(encrypted_message)
    salt = decoded_data[:16]
    iv = decoded_data[16:28]
    tag = decoded_data[28:44]
    ciphertext = decoded_data[44:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Función para cifrar archivos
def cifrar_archivo():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = entry_contrasena.get()
        if password:
            with open(file_path, 'rb') as file:
                data = file.read()
            encrypted_data = encrypt_aes_gcm(data, password)
            save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
            with open(save_path, 'wb') as file:
                file.write(encrypted_data)
            messagebox.showinfo("Éxito", "El archivo ha sido cifrado.")
        else:
            messagebox.showwarning("Advertencia", "Por favor, ingresa una contraseña.")

# Función para descifrar archivos
def descifrar_archivo():
    global intentos_fallidos
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        password = entry_contrasena.get()
        if password:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            try:
                decrypted_data = decrypt_aes_gcm(encrypted_data, password)
                save_path = filedialog.asksaveasfilename(defaultextension=".dec", filetypes=[("Decrypted Files", "*.dec")])
                with open(save_path, 'wb') as file:
                    file.write(decrypted_data)
                messagebox.showinfo("Éxito", "El archivo ha sido descifrado.")
                intentos_fallidos = 0  # Reiniciar intentos fallidos
            except Exception as e:
                intentos_fallidos += 1
                if intentos_fallidos >= 4:
                    os.remove(file_path)
                    messagebox.showerror("Error", "El archivo ha sido eliminado tras 4 intentos fallidos.")
                else:
                    messagebox.showerror("Error", f"Contraseña incorrecta. Intentos fallidos: {intentos_fallidos}")
        else:
            messagebox.showwarning("Advertencia", "Por favor, ingresa una contraseña.")

# Función para cifrar mensajes
def cifrar_mensaje():
    mensaje = text_mensaje.get("1.0", "end").strip()
    password = entry_contrasena_mensaje.get()
    if mensaje and password:
        encrypted_message = encrypt_aes_gcm(mensaje.encode(), password)
        text_mensaje.delete("1.0", "end")
        text_mensaje.insert("1.0", encrypted_message.decode())
        messagebox.showinfo("Éxito", "El mensaje ha sido cifrado.")
    else:
        messagebox.showwarning("Advertencia", "Por favor, ingresa un mensaje y una contraseña.")

# Función para descifrar mensajes
def descifrar_mensaje():
    global intentos_fallidos
    encrypted_message = text_mensaje.get("1.0", "end").strip()
    password = entry_contrasena_mensaje.get()
    if encrypted_message and password:
        try:
            decrypted_message = decrypt_aes_gcm(encrypted_message.encode(), password).decode()
            text_mensaje.delete("1.0", "end")
            text_mensaje.insert("1.0", decrypted_message)
            messagebox.showinfo("Éxito", "El mensaje ha sido descifrado.")
            intentos_fallidos = 0
        except Exception as e:
            intentos_fallidos += 1
            if intentos_fallidos >= 4:
                messagebox.showerror("Error", "Demasiados intentos fallidos.")
                text_mensaje.delete("1.0", "end")
            else:
                messagebox.showerror("Error", f"Contraseña incorrecta. Intentos fallidos: {intentos_fallidos}")
    else:
        messagebox.showwarning("Advertencia", "Por favor, ingresa un mensaje cifrado y una contraseña.")

# Función para generar una contraseña aleatoria de 21 caracteres
def generar_contrasena():
    caracteres = string.ascii_letters + string.digits + string.punctuation
    contrasena = ''.join(random.choice(caracteres) for i in range(21))
    entry_contrasena_generada.delete(0, "end")
    entry_contrasena_generada.insert(0, contrasena)

# Crear ventana principal
ventana = tk.Tk()
ventana.title("Cifrado y Descifrado de Archivos y Mensajes")

# Crear el Notebook (pestañas)
notebook = ttk.Notebook(ventana)
notebook.pack(pady=10, expand=True)

# Crear frames para las pestañas de cifrado y descifrado
tab_cifrar_archivo = ttk.Frame(notebook)
tab_descifrar_archivo = ttk.Frame(notebook)
tab_cifrar_mensaje = ttk.Frame(notebook)
tab_descifrar_mensaje = ttk.Frame(notebook)
tab_generar_contrasena = ttk.Frame(notebook)

notebook.add(tab_cifrar_archivo, text='Cifrar Archivo')
notebook.add(tab_descifrar_archivo, text='Descifrar Archivo')
notebook.add(tab_cifrar_mensaje, text='Cifrar Mensaje')
notebook.add(tab_descifrar_mensaje, text='Descifrar Mensaje')
notebook.add(tab_generar_contrasena, text='Generar Contraseña')

# ---- Pestaña Cifrar Archivos ----
tk.Label(tab_cifrar_archivo, text="Contraseña:").pack(pady=5)
entry_contrasena = tk.Entry(tab_cifrar_archivo, show='*', width=50)
entry_contrasena.pack(pady=5)
btn_cifrar_archivo = tk.Button(tab_cifrar_archivo, text="Cifrar Archivo", command=cifrar_archivo)
btn_cifrar_archivo.pack(pady=10)

# ---- Pestaña Descifrar Archivos ----
tk.Label(tab_descifrar_archivo, text="Contraseña:").pack(pady=5)
entry_contrasena = tk.Entry(tab_descifrar_archivo, show='*', width=50)
entry_contrasena.pack(pady=5)
btn_descifrar_archivo = tk.Button(tab_descifrar_archivo, text="Descifrar Archivo", command=descifrar_archivo)
btn_descifrar_archivo.pack(pady=10)

# ---- Pestaña Cifrar Mensajes ----
tk.Label(tab_cifrar_mensaje, text="Mensaje:").pack(pady=5)
text_mensaje = tk.Text(tab_cifrar_mensaje, height=10, width=50)
text_mensaje.pack(pady=5)
tk.Label(tab_cifrar_mensaje, text="Contraseña:").pack(pady=5)
entry_contrasena_mensaje = tk.Entry(tab_cifrar_mensaje, show='*', width=50)
entry_contrasena_mensaje.pack(pady=5)
btn_cifrar_mensaje = tk.Button(tab_cifrar_mensaje, text="Cifrar Mensaje", command=cifrar_mensaje)
btn_cifrar_mensaje.pack(pady=10)

# ---- Pestaña Descifrar Mensajes ----
tk.Label(tab_descifrar_mensaje, text="Mensaje cifrado:").pack(pady=5)
text_mensaje = tk.Text(tab_descifrar_mensaje, height=10, width=50)
text_mensaje.pack(pady=5)
tk.Label(tab_descifrar_mensaje, text="Contraseña:").pack(pady=5)
entry_contrasena_mensaje = tk.Entry(tab_descifrar_mensaje, show='*', width=50)
entry_contrasena_mensaje.pack(pady=5)
btn_descifrar_mensaje = tk.Button(tab_descifrar_mensaje, text="Descifrar Mensaje", command=descifrar_mensaje)
btn_descifrar_mensaje.pack(pady=10)

# ---- Pestaña Generar Contraseña ----
tk.Label(tab_generar_contrasena, text="Contraseña generada:").pack(pady=5)
entry_contrasena_generada = tk.Entry(tab_generar_contrasena, width=50)
entry_contrasena_generada.pack(pady=5)
btn_generar_contrasena = tk.Button(tab_generar_contrasena, text="Generar Contraseña", command=generar_contrasena)
btn_generar_contrasena.pack(pady=10)

# Ejecutar ventana
ventana.mainloop()
