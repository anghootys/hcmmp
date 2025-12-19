import hmac
from os import mkdir
from os.path import isdir, isfile

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import base64
import logging

lg = logging.getLogger("HCMMP_CRYPTO_UTILS")


def generate_pub_key_fingerprint(pub_key: RSAPublicKey):
    key_bytes = pub_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_fingerprint = base64.b64encode(hashlib.sha256(key_bytes).digest())
    return key_fingerprint


def checksum_pub_key(host_id: str, fingerprint: bytes) -> bool:
    try:
        with open("./.keys/known_hosts", 'r') as f:
            known_hosts_list = f.readlines()
            filtered_hosts = list(filter(lambda host: host.split(" ")[0] == str(host_id), known_hosts_list))
            if len(filtered_hosts) == 0:
                lg.warning(f"No known host entry for host ID {host_id}.")
                return False
            elif len(filtered_hosts) > 1:
                lg.warning(f"Multiple known host entries for host ID {host_id}, using the first one.")
                host_fingerprint = filtered_hosts[0].split(" ")[1].strip().encode()
                if host_fingerprint == fingerprint:
                    return True
                else:
                    lg.error(f"Fingerprint mismatch for host ID {host_id}.")
                    return False
            else:
                host_fingerprint = filtered_hosts[0].split(" ")[1].strip().encode()
                if host_fingerprint == fingerprint:
                    return True
                else:
                    lg.error(f"Fingerprint mismatch for host ID {host_id}.")
                    return False

    except Exception as e:
        lg.error(f"Could not perform checksum: {e}")
        return False


def store_fingerprint(host_id: str, fingerprint: bytes):
    try:
        if not isdir("./.keys"):
            lg.info("Creating .keys directory.")
            mkdir("./.keys")

        old_known_hosts = []
        if isfile("./.keys/known_hosts"):
            with open("./.keys/known_hosts", 'r') as f:
                old_known_hosts = f.readlines()

        with open("./.keys/known_hosts", 'w') as f:
            filtered_hosts = list(filter(lambda host: host.split(" ")[0] != str(host_id), old_known_hosts))
            f.writelines(filtered_hosts)
            f.write(f"{host_id} {fingerprint.decode()}\n")

        lg.info(f"Stored fingerprint for host ID {host_id}.")
    except Exception as e:
        lg.error(f"Could not store fingerprint: {e}")


def encrypt_with_rsa_pub_key(pub_key: RSAPublicKey, data: bytes):
    return pub_key.encrypt(plaintext=data, padding=padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))


def decrypt_rsa_ciphertext(prv_key: RSAPrivateKey, ciphertext: bytes):
    return prv_key.decrypt(ciphertext, padding=padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
