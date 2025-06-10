## @file
#  @brief RSA key generator with encryption and USB storage support.
#
#  This module allows the user to generate a 4096-bit RSA key pair,
#  encrypt the private key using a user-defined PIN,
#  and store the encrypted private key on a removable USB drive.
#
#  It also provides a simple GUI using Tkinter for interactive use.

import os
import psutil
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import tkinter as tk
from tkinter import messagebox, ttk

private_key = None
public_key = None

##
# @brief Generates an RSA key pair and saves it to PEM files.
#
# This function creates a 4096-bit RSA key pair and saves the public and private keys 
# to 'public.pem' and 'private.pem'. It also updates global variables.
def generate_rsa_keys():
    global private_key, public_key
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open('public.pem', 'wb') as f:
        f.write(public_key)
    with open('private.pem', 'wb') as f:
        f.write(private_key)

    messagebox.showinfo("Sukces", "Wygenerowano parę kluczy RSA (4096 bitów).")

##
# @brief Detects removable USB drives.
#
# @return A list of drive letters representing removable USB drives.
def get_usb_drives():
    drives = []
    for part in psutil.disk_partitions():
        if 'removable' in part.opts.lower() or part.device.startswith("F:") or part.device.startswith("E:"):
            drives.append(part.device)
    return drives

##
# @brief Encrypts the private RSA key with a password and stores it on a USB drive.
#
# @param pin A string PIN used to derive the encryption key.
# @param usb_path The path to the USB drive where the encrypted key will be stored.
# @return True if the encryption and saving was successful, False otherwise.
def encrypt_private_key(pin, usb_path):
    global private_key
    salt = get_random_bytes(16)
    key = scrypt(pin.encode(), salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)

    output_file = os.path.join(usb_path, "encrypted_private_key.bin")
    try:
        with open(output_file, "wb") as f:
            for x in (salt, cipher.nonce, tag, ciphertext):
                f.write(x)
        return True
    except Exception as e:
        print(f"Błąd zapisu na dysku: {e}")
        return False

##
# @brief Validates inputs and initiates the encryption process.
#
# @param pin_entry Tkinter Entry widget where the user enters the PIN.
# @param usb_combo Tkinter Combobox widget for selecting the USB drive.
def on_submit(pin_entry, usb_combo):
    global private_key
    pin = pin_entry.get()
    if not private_key:
        messagebox.showerror("Błąd", "Najpierw wygeneruj klucze RSA.")
        return
    if len(pin) < 4:
        messagebox.showerror("Błąd", "PIN musi mieć przynajmniej 4 znaki.")
        return
    usb_path = usb_combo.get()
    if not usb_path:
        messagebox.showerror("Błąd", "Wybierz dysk.")
        return
    success = encrypt_private_key(pin, usb_path)
    if success:
        messagebox.showinfo("Sukces", "Klucz zaszyfrowany i zapisany na dysk.")
    else:
        messagebox.showerror("Błąd", "Nie udało się zapisać klucza na dysk.")

##
# @brief Creates and runs the graphical user interface for the application.
#
# This GUI allows users to generate RSA keys and store the encrypted private key on a USB drive.
def create_gui():
    root = tk.Tk()
    root.title("RSA Key Generator")
    root.geometry("400x250")

    generate_button = tk.Button(root, text="Generuj klucze RSA", command=generate_rsa_keys)
    generate_button.pack(pady=10)

    tk.Label(root, text="Podaj PIN:").pack()
    pin_entry = tk.Entry(root, show="*")
    pin_entry.pack()

    tk.Label(root, text="Wybierz dysk:").pack()
    usb_drives = get_usb_drives()
    if not usb_drives:
        usb_drives = [""]
    usb_combo = ttk.Combobox(root, values=usb_drives, state="readonly")
    usb_combo.pack()
    if usb_drives:
        usb_combo.current(0)

    submit_button = tk.Button(root, text="Zapisz klucz na dysku", command=lambda: on_submit(pin_entry, usb_combo))
    submit_button.pack(pady=10)

    root.mainloop()

##
# @brief Entry point of the application.
if __name__ == "__main__":
    create_gui()
