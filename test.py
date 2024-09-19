'''
Libraries to consider using

cryptography 
tkinter: A Python library for creating simple graphical user interfaces (GUIs).
virtualenv or venv: Tools for creating isolated virtual Python environments, useful for managing project dependencies.
SQLAlchemy: A popular Python library for working with SQL databases, providing a higher-level ORM (Object-Relational Mapping) framework.
socket: A Python module for network programming, allowing you to create networked applications.
unittest: A built-in Python library for writing and running unit tests for your code.
Sphinx: A documentation generation tool that can help you create comprehensive project documentation.

---

Also consider some type of RSA-specific backend, not sure if the default is good enough or not...
'''
from encryption import *

TEST_PUBLIC_KEY_FNAME = "keys/test_public_key"
TEST_PRIVATE_KEY_FNAME = "keys/test_private_key"
TEST_MESSAGE = b"Ohayou sekai!"
TEST_PASSWORD = b"password"

#Generate the keys
public_key = genkeys(TEST_PUBLIC_KEY_FNAME, TEST_PRIVATE_KEY_FNAME, TEST_PASSWORD)

#load private_key from file
private_key = load_key(TEST_PRIVATE_KEY_FNAME + ".pem", TEST_PASSWORD)

#Sign the message
signature = sign_message(TEST_MESSAGE, private_key)

#Encrypt the message
ciphertext = encrypt_message(public_key, TEST_MESSAGE)

#assert that the message is encrypted
assert ciphertext != TEST_MESSAGE

#Verify the signature
verify_key(private_key.public_key(), TEST_MESSAGE, signature)

#decrypt the message
plaintext = decrypt_message(private_key, ciphertext)

#assert original message is the same as decrypted message
assert TEST_MESSAGE == plaintext

#print decrypted message
print(plaintext)