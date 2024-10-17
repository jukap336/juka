# Función para cifrar archivos
def cifrar_archivo():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = entry_contrasena.get()
        if password:
            try:
                with open(file_path, 'rb') as file:
                    data = file.read()
                encrypted_data = encrypt_aes_gcm(data, password)
                
                # Guardar archivo cifrado
                save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
                if save_path:
                    with open(save_path, 'wb') as file:
                        file.write(encrypted_data)
                    messagebox.showinfo("Éxito", "El archivo ha sido cifrado.")
            except Exception as e:
                messagebox.showerror("Error", f"Error al cifrar el archivo: {e}")
        else:
            messagebox.showwarning("Advertencia", "Por favor, ingresa una contraseña.")

# Función para descifrar archivos
def descifrar_archivo():
    global intentos_fallidos
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        password = entry_contrasena.get()
        if password:
            try:
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()
                
                decrypted_data = decrypt_aes_gcm(encrypted_data, password)
                
                # Guardar archivo descifrado
                save_path = filedialog.asksaveasfilename(defaultextension=".dec", filetypes=[("Decrypted Files", "*.dec")])
                if save_path:
                    with open(save_path, 'wb') as file:
                        file.write(decrypted_data)
                    messagebox.showinfo("Éxito", "El archivo ha sido descifrado.")
                    intentos_fallidos = 0
            except Exception as e:
                intentos_fallidos += 1
                if intentos_fallidos >= 4:
                    os.remove(file_path)
                    messagebox.showerror("Error", "El archivo ha sido eliminado tras 4 intentos fallidos.")
                else:
                    messagebox.showerror("Error", f"Contraseña incorrecta. Intentos fallidos: {intentos_fallidos}. Error: {e}")
        else:
            messagebox.showwarning("Advertencia", "Por favor, ingresa una contraseña.")

