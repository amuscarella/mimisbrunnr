from cryptography.fernet import Fernet

# Put this somewhere safe!
key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"A really secret message. Not for prying eyes.")
print(token)

decoded_msg = f.decrypt(token)

print(decoded_msg)