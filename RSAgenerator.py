from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

key = RSA.generate(4096)

with open('public.pem', 'wb') as f:
    f.write(key.publickey().export_key())
    
with open('private.pem', 'wb') as f:
    f.write(key.export_key())
