from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt


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

if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys() 
    encrypt_private_key(private_key, "1234")  