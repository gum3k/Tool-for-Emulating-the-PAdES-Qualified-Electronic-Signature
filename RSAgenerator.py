from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import tkinter as tk
from tkinter import messagebox

def generate_rsa_keys():
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open('public.pem', 'wb') as f:
        f.write(public_key)
        
    with open('private.pem', 'wb') as f:
        f.write(private_key)

    return private_key, public_key

def encrypt_private_key(private_key, pin):
    salt = get_random_bytes(16) 
    key = scrypt(pin.encode(), salt, 32, N=2**14, r=8, p=1)  
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)
    
    with open("encrypted_private_key.bin", "wb") as f:
        for x in (salt, cipher.nonce, tag, ciphertext):
            f.write(x)
    
    return cipher.nonce, tag, ciphertext

def on_submit(pin_entry, private_key):
    pin = pin_entry.get()
    if len(pin) < 4: 
        messagebox.showerror("Error", "PIN must be at least 4 characters long")
        return
    
    nonce, tag, ciphertext = encrypt_private_key(private_key, pin)

    messagebox.showinfo("Success", "Private key encrypted successfully")

def create_gui():
    root = tk.Tk()
    root.title("Siging PDF documents")
    root.geometry("500x400")

    tk.Label(root, text="Enter PIN:").pack()

    pin_entry = tk.Entry(root, show="*") 
    pin_entry.pack()

    submit_button = tk.Button(root, text="Submit", command=lambda: on_submit(pin_entry, private_key))
    submit_button.pack()

    root.mainloop()

if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys() 
    create_gui() 