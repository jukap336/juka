import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

# Variable para almacenar intentos fallidos
intentos_fallidos = 0

# Función para derivar clave criptográfica a partir de una contraseña
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Función para cifrar un mensaje con AES en modo GCM
def encrypt_aes_gcm(message: bytes, password: str) -> bytes:
    salt = os.urandom(16)  # Genera una sal aleatoria
    key = derive_key(password, salt)  # Deriva la clave usando la sal
    iv = os.urandom(12)  # Genera un vector de inicialización (IV) aleatorio
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    # Combina la sal, IV, tag y ciphertext, luego codifica en Base64
    return urlsafe_b64encode(salt + iv + encryptor.tag + ciphertext)

# Función para descifrar un mensaje cifrado con AES en modo GCM
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
        print(f"Contraseña ingresada para cifrar: {password}")  # Depuración
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
        print(f"Contraseña ingresada para descifrar: {password}")  # Depuración
        if password:
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            try:
                decrypted_data = decrypt_aes_gcm(encrypted_data, password)
                save_path = filedialog.asksaveasfilename(defaultextension=".dec", filetypes=[("Decrypted Files", "*.dec")])
                with open(save_path, 'wb') as file:
                    file.write(decrypted_data)
                messagebox.showinfo("Éxito", "El archivo ha sido descifrado.")
                intentos_fallidos = 0  # Reiniciar los intentos fallidos si se descifra correctamente
            except Exception as e:
                intentos_fallidos += 1
                if intentos_fallidos >= 4:
                    # Eliminar el archivo tras 4 intentos fallidos
                    os.remove(file_path)
                    messagebox.showerror("Error", "El archivo ha sido eliminado tras 4 intentos fallidos.")
                else:
                    messagebox.showerror("Error", f"Contraseña incorrecta. Intentos fallidos: {intentos_fallidos}")
        else:
            messagebox.showwarning("Advertencia", "Por favor, ingresa una contraseña.")

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("Cifrado y Descifrado AES GCM")

# Crear un Notebook (pestañas)
notebook = ttk.Notebook(ventana)
notebook.pack(pady=10, expand=True)

# Crear los frames para las dos pestañas
tab_cifrar = ttk.Frame(notebook)
tab_descifrar = ttk.Frame(notebook)

notebook.add(tab_cifrar, text='Cifrar')
notebook.add(tab_descifrar, text='Descifrar')

# ---- PESTAÑA CIFRAR ----
# Crear y colocar etiquetas y campos de entrada
tk.Label(tab_cifrar, text="Contraseña:").pack(pady=5)
entry_contrasena = tk.Entry(tab_cifrar, show='*', width=50)
entry_contrasena.pack(pady=5)

# Crear y colocar botones para cifrar archivos
btn_cifrar_archivo = tk.Button(tab_cifrar, text="Cifrar Archivo", command=cifrar_archivo)
btn_cifrar_archivo.pack(pady=10)

# ---- PESTAÑA DESCIFRAR ----
# Crear y colocar etiquetas y campos de entrada para descifrar
tk.Label(tab_descifrar, text="Contraseña:").pack(pady=5)
entry_contrasena = tk.Entry(tab_descifrar, show='*', width=50)
entry_contrasena.pack(pady=5)

# Crear y colocar botones para descifrar archivos
btn_descifrar_archivo = tk.Button(tab_descifrar, text="Descifrar Archivo", command=descifrar_archivo)
btn_descifrar_archivo.pack(pady=10)

# Iniciar el bucle principal de la interfaz
ventana.mainloop()
