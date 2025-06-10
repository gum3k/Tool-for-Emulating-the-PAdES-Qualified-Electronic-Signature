import os
import psutil
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA256
from PyPDF2 import PdfReader, PdfWriter

private_key = None
pdf_path = None
key_file_path = None
public_key = None
signed_pdf_path = None

def find_usb_key(label=None):
    global key_file_path
    for part in psutil.disk_partitions():
        if 'removable' in part.opts.lower():
            usb_path = part.mountpoint
            possible = os.path.join(usb_path, "encrypted_private_key.bin")
            if os.path.exists(possible):
                key_file_path = possible
                if label:
                    label.config(text=f"Znaleziono klucz: {key_file_path}")
                messagebox.showinfo("Sukces", f"Znaleziono klucz na: {key_file_path}")
                return
    if label:
        label.config(text="Nie znaleziono klucza na pendrive.")
    messagebox.showerror("Błąd", "Nie znaleziono klucza na żadnym pendrive.")



def decrypt_private_key(pin):
    global private_key
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
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        private_key = RSA.import_key(decrypted)
        return True
    except Exception as e:
        messagebox.showerror("Błąd", f"Nie udało się odszyfrować klucza:\n{e}")
        return False


def select_pdf_to_sign():
    global pdf_path
    path = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
    if path:
        pdf_path = path
        messagebox.showinfo("PDF", f"Wybrano: {path}")


def sign_pdf_embed():
    global pdf_path, private_key
    if not private_key or not pdf_path:
        messagebox.showerror("Błąd", "Brak klucza prywatnego lub pliku PDF.")
        return
    try:
        reader = PdfReader(pdf_path)
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        data = b"".join([page.extract_text().encode() for page in reader.pages])

        h = SHA256.new(data)
        signature = pkcs1_15.new(private_key).sign(h)

        writer.add_metadata({
            "/Signature": signature.hex(),
        })

        signed_path = pdf_path.replace(".pdf", "_signed.pdf")
        with open(signed_path, "wb") as f:
            writer.write(f)

        messagebox.showinfo("Sukces", f"PDF podpisany jako: {signed_path}")
    except Exception as e:
        messagebox.showerror("Błąd", f"Podpisanie nie powiodło się:\n{e}")


def select_signed_pdf():
    global signed_pdf_path
    path = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf"), ("Podpisane PDF", "*.pdf"), ("Pliki", "*.pdf*"), ("Wszystkie", "*.*")])
    if path:
        signed_pdf_path = path
        messagebox.showinfo("PDF", f"Wybrano: {signed_pdf_path}")


def select_public_key():
    global public_key
    path = filedialog.askopenfilename(filetypes=[("PEM", "*.pem")])
    if path:
        try:
            with open(path, "rb") as f:
                public_key = RSA.import_key(f.read())
            messagebox.showinfo("Klucz", "Załadowano klucz publiczny.")
            return
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie udało się wczytać klucza:\n{e}")


def verify_pdf_signature():
    global signed_pdf_path, public_key
    if not signed_pdf_path or not public_key:
        messagebox.showerror("Błąd", "Brak pliku PDF lub klucza publicznego.")
        return
    try:
        reader = PdfReader(signed_pdf_path)
        signature_hex = reader.metadata.get("/Signature", "")

        if not signature_hex:
            messagebox.showerror("Błąd", "Brak podpisu w pliku PDF.")
            return
        signature = bytes.fromhex(signature_hex)
        neutralized_data = b"".join([page.extract_text().encode() for page in reader.pages])
        if len(signature) != 512:
            messagebox.showerror("Błąd", "Nieprawidłowy podpis. Oczekiwano 512 bajtów.")
            return
        h = SHA256.new(neutralized_data)
        pkcs1_15.new(public_key).verify(h, signature)
        messagebox.showinfo("Weryfikacja", "Podpis poprawny.")
    except Exception as e:
        messagebox.showerror("Weryfikacja", f"Podpis nieprawidłowy lub błąd:\n{e}")


def create_gui():
    root = Tk()
    root.title("PAdES Podpis i Weryfikacja")
    root.geometry("500x460")

    notebook = ttk.Notebook(root)
    notebook.pack(fill=BOTH, expand=True)

    sign_tab = Frame(notebook)
    notebook.add(sign_tab, text="Podpisz dokument")

    usb_key_label = Label(sign_tab, text="", wraplength=480, fg="gray")
    usb_key_label.pack()
    Button(sign_tab, text="Wykryj klucz prywatny na USB", command=lambda: find_usb_key(usb_key_label)).pack(pady=5)


    Label(sign_tab, text="PIN do klucza prywatnego:").pack()
    pin_var = StringVar()
    Entry(sign_tab, textvariable=pin_var, show="*").pack()

    def load_key():
        pin = pin_var.get()
        if not pin:
            messagebox.showerror("Błąd", "Wprowadź PIN.")
            return
        if decrypt_private_key(pin):
            messagebox.showinfo("Sukces", "Klucz odszyfrowany.")

    Button(sign_tab, text="Załaduj klucz", command=load_key).pack(pady=5)

    Button(sign_tab, text="Wybierz PDF", command=select_pdf_to_sign).pack(pady=5)
    pdf_label = Label(sign_tab, text="", wraplength=480, fg="gray")
    pdf_label.pack()

    Button(sign_tab, text="Podpisz PDF", command=sign_pdf_embed).pack(pady=5)

    verify_tab = Frame(notebook)
    notebook.add(verify_tab, text="Zweryfikuj podpis")

    Button(verify_tab, text="Wybierz podpisany PDF", command=select_signed_pdf).pack(pady=5)
    signed_pdf_label = Label(verify_tab, text="", wraplength=480, fg="gray")
    signed_pdf_label.pack()

    Button(verify_tab, text="Wybierz klucz publiczny", command=select_public_key).pack(pady=5)
    pubkey_label = Label(verify_tab, text="", wraplength=480, fg="gray")
    pubkey_label.pack()

    Button(verify_tab, text="Zweryfikuj podpis", command=verify_pdf_signature).pack(pady=5)

    def select_pdf_to_sign_local():
        select_pdf_to_sign()
        if pdf_path:
            pdf_label.config(text=f"Wybrany PDF: {pdf_path}")

    def select_signed_pdf_local():
        select_signed_pdf()
        if signed_pdf_path:
            signed_pdf_label.config(text=f"Podpisany PDF: {signed_pdf_path}")

    def select_public_key_local():
        select_public_key()
        if public_key:
            pubkey_label.config(text="Klucz publiczny załadowany")

    for widget in sign_tab.winfo_children():
        if isinstance(widget, Button) and widget["text"] == "Wybierz PDF":
            widget.config(command=select_pdf_to_sign_local)
    for widget in verify_tab.winfo_children():
        if isinstance(widget, Button):
            if widget["text"] == "Wybierz podpisany PDF":
                widget.config(command=select_signed_pdf_local)
            elif widget["text"] == "Wybierz klucz publiczny":
                widget.config(command=select_public_key_local)

    root.mainloop()


if __name__ == "__main__":
    create_gui()
