'''
Libraries to consider using, courtesy of ChatGPT lol

cryptography: obviously lol 

tkinter: A Python library for creating simple graphical user interfaces (GUIs).

virtualenv or venv: Tools for creating isolated virtual Python environments, useful for managing project dependencies.

SQLAlchemy: A popular Python library for working with SQL databases, providing a higher-level ORM (Object-Relational Mapping) framework.

socket: A Python module for network programming, allowing you to create networked applications.

unittest: A built-in Python library for writing and running unit tests for your code.

Sphinx: A documentation generation tool that can help you create comprehensive project documentation.


---

Also consider some type of RSA-specific backend, not sure if the default is good enough or not...
'''

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

public_key = private_key.public_key()

msg = b"Ohayou sekai!"
ciphertext = public_key.encrypt(
    msg,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(ciphertext)

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(plaintext == msg)