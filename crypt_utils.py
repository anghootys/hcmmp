from os import mkdir
from os.path import isdir

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


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