import logging
import os.path
from os import mkdir, access, R_OK
from os.path import isdir

from getpass import getpass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TAG = "CRYPT_UTILS"

lg = logging.getLogger(TAG)

def generate_prv_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def serialize_prv_pub_keys_to_pem(private_key, encryption_pass_phrase=None):
    pem_prv_buf = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(
            encryption_pass_phrase.encode()) if encryption_pass_phrase else serialization.NoEncryption()
    )

    pem_pub_buf = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "prv_key": pem_prv_buf,
        "pub_key": pem_pub_buf
    }

def save_pem_to(path_prefix, files_prefix, pem_buf):
    if not isdir(path_prefix):
        mkdir(path_prefix)

    def _save_pem(buf, file_path):
        try:
            with open(file_path, 'wb') as f:
                f.write(buf)
        except Exception as e:
            print(f"Error saving PEM file {file_path}: {e}")

    _save_pem(pem_buf['prv_key'], f"{path_prefix}/{files_prefix}_prv.pem")
    _save_pem(pem_buf['pub_key'], f"{path_prefix}/{files_prefix}_pub.pem")

def _is_passphrase_required_for_prv_pem(file_path):
    with open(file_path, 'rb') as f:
        prv_pem_data = f.read()

    try:
        serialization.load_pem_private_key(prv_pem_data, password=None)
        return False
    except TypeError:
        return True

def load_prv_pem(file_path):
    if not access(file_path, R_OK):
        raise PermissionError(f"No access to private key file '{file_path}'.")

    passphrase = None

    if _is_passphrase_required_for_prv_pem(file_path):
        lg.info("Private key is encrypted. Prompting for passphrase.")
        passphrase = getpass(f"Enter passphrase for private key pem file '{os.path.realpath(file_path)}': ").rstrip()

    with open(file_path, 'rb') as prv_pem_file:
        prv_key = serialization.load_pem_private_key(prv_pem_file.read(), password=passphrase.encode() if passphrase else None)

        return prv_key

def load_pub_pem(file_path):
    if not access(file_path, R_OK):
        raise PermissionError(f"No access to public key file '{file_path}'.")

    with open(file_path, 'rb') as pub_pem_file:
        pub_key = serialization.load_pem_public_key(pub_pem_file.read())

        return pub_key
