import os
import psutil
import pikepdf
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA256
from tkinter import Tk, Button, Label, Entry, filedialog, messagebox, StringVar

key_file_path = None
private_key = None
pdf_path = None

def find_usb_key():
    global key_file_path
    found = False
    for part in psutil.disk_partitions():
        if 'removable' in part.opts.lower():
            usb_path = part.mountpoint
            possible = os.path.join(usb_path, "encrypted_private_key.bin")
            if os.path.exists(possible):
                key_file_path = possible
                messagebox.showinfo("Sukces", f"Znaleziono klucz na: {key_file_path}")
                found = True
                break
    if not found:
        messagebox.showerror("Błąd", "Nie znaleziono klucza na żadnym pendrive.")

def decrypt_private_key(pin):
    global private_key, key_file_path
    if not key_file_path:
        messagebox.showerror("Błąd", "Najpierw wykryj klucz.")
        return False
    try:
        with open(key_file_path, "rb") as f:
            salt = f.read(16)
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()
        key = scrypt(pin.encode(), salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_key = cipher.decrypt_and_verify(ciphertext, tag)
        private_key = RSA.import_key(decrypted_key)
        return True
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się odszyfrować klucza:\n{e}")
        return False

def select_pdf():
    global pdf_path
    selected = filedialog.askopenfilename(title="Wybierz plik PDF", filetypes=[("PDF", "*.pdf")])
    if selected:
        pdf_path = selected
        messagebox.showinfo("Plik PDF", f"Wybrano: {pdf_path}")

def sign_pdf_and_embed():
    global private_key, pdf_path
    if not private_key:
        messagebox.showerror("Błąd", "Nie załadowano klucza prywatnego.")
        return
    if not pdf_path:
        messagebox.showerror("Błąd", "Nie wybrano pliku PDF.")
        return
    try:
        with open(pdf_path, "rb") as f:
            pdf_data = f.read()

        h = SHA256.new(pdf_data)
        signature = pkcs1_15.new(private_key).sign(h)

        with pikepdf.open(pdf_path) as pdf:
            pdf.docinfo["/SignedBy"] = "User A"
            pdf.docinfo["/Signature"] = signature.hex()
            output_path = pdf_path.replace(".pdf", "_signed.pdf")
            pdf.save(output_path)

        messagebox.showinfo("Sukces", f"PDF podpisany i zapisany jako:\n{output_path}")
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się podpisać pliku:\n{e}")

def create_gui():
    root = Tk()
    root.title("Podpisywanie PDF")
    root.geometry("420x320")

    Button(root, text="Wykryj klucz na USB", command=find_usb_key).pack(pady=5)

    Label(root, text="Wprowadź PIN do odszyfrowania klucza prywatnego:").pack(pady=5)
    pin_var = StringVar()
    pin_entry = Entry(root, textvariable=pin_var, show="*")
    pin_entry.pack()

    def load_key():
        pin = pin_var.get()
        if not pin:
            messagebox.showerror("Błąd", "Wprowadź PIN.")
            return
        if decrypt_private_key(pin):
            messagebox.showinfo("Sukces", "Klucz odszyfrowany poprawnie.")

    Button(root, text="Załaduj klucz", command=load_key).pack(pady=10)
    Button(root, text="Wybierz PDF", command=select_pdf).pack(pady=10)
    Button(root, text="Podpisz PDF", command=sign_pdf_and_embed).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
