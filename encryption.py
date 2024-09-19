from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def genkeys(public_key_fname, private_key_fname, password):
    """
    Generates private and public keys using RSA encryption.
    :param public_key_fname: (str) denoting the filename for the public key
    :param private_key_fname: (str) denoting the filename for the private key
    :param password: (byte str) password for private key file
    :return: the public key object
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    #serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    #write private key to .pem file
    f = open(private_key_fname + ".pem", 'wb')
    f.write(private_pem)
    f.close()

    #serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    #write public key to .pem file
    f = open(public_key_fname + ".pem", 'wb') 
    f.write(public_pem)
    f.close()

    return(public_key)

def load_key(key_fname, password):
    """
    Loads a private key from a .pem file on disk.
    :param key_fname: (str) the full path to the .pem private key file
    :param password: (byte str) the password for the private key file
    :return: the private key object
    """
    with open(key_fname, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            backend=default_backend(),
            password=password
        )
    return(private_key)

def sign_message(message, private_key):
    """
    Signs a message with a private_key
    :param message: (byte str) the message to be signed
    :param private_key: private key object with which to sign message
    :return: signature object
    """
    return(private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH #TODO: add capability for larger messages using prehashed 
        ),
        hashes.SHA256()
    ))

def verify_key(public_key, message, signature):
    """
    Verifies a message was signed with the corresponding private key of the given public key
    :param public_key: public key object
    :param message: (str) the message
    :param signature: the signature
    :return: True, raise exception otherwise
    """
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH #TODO: handle arbitrarily long messages with prehashing
        ),
        hashes.SHA256()
    )
    
def encrypt_message(public_key, message):
    '''
    encrypts a message using a public_key
    :param public_key: the public key object
    :param message: (byte str) the bytestring message to be encrypted
    '''
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return(ciphertext)

def decrypt_message(private_key, ciphertext):
    """
    Decrypts a ciphertext using a private key
    :param private_key: the private key object
    :param ciphertext: the ciphertext
    :return: (str) the decrypted plaintext message
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return(plaintext)