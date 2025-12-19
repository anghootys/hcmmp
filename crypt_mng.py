import logging
import os
from os import listdir, access
from os.path import isdir

from getpass import getpass

from crypt_utils import load_prv_pem, load_pub_pem

TAG = "CRYPT_MNG"

KEYS_PATH = "./.keys"

prv_key = None
pub_key = None


def handle_encryption_keys():
    global prv_key, pub_key
    lg = logging.getLogger(TAG)

    def generate_default_keys():
        global prv_key, pub_key
        from crypt_utils import generate_prv_key, serialize_prv_pub_keys_to_pem, save_pem_to

        passphrase = getpass(
            "No encryption keys found. Generating new keys.\nEnter passphrase for private key (leave empty for no encryption): ").rstrip()
        if passphrase == "":
            passphrase = None

        prv_key = generate_prv_key()
        pub_key = prv_key.public_key()
        _pem_buf = serialize_prv_pub_keys_to_pem(prv_key, passphrase)
        save_pem_to(KEYS_PATH, "default", _pem_buf)

    if isdir(KEYS_PATH) and not access(KEYS_PATH, os.R_OK | os.W_OK):
        raise PermissionError(f"No access to keys directory '{KEYS_PATH}'.")

    if not isdir(KEYS_PATH):
        lg.warning(f"dir '{KEYS_PATH}' does not exist.")
        lg.info("Generating new default encryption keys.")

        generate_default_keys()

    else:
        lg.info(f"dir '{KEYS_PATH}' exists. Loading existing encryption keys.")

        key_files = listdir(KEYS_PATH)
        if not any(f.endswith('_prv.pem') for f in key_files) or not any(f.endswith('_pub.pem') for f in key_files):
            lg.warning(f"Keys not found in '{KEYS_PATH}'.")
            lg.info("Generating new default encryption keys.")
            generate_default_keys()
        else:
            lg.info("Encryption keys found.")
            if "default_prv.pem" not in key_files or "default_pub.pem" not in key_files:
                lg.warning("Default keys not found.")

                for i, file in enumerate(key_files):
                    print(f"{i + 1}) {file}")

                while True:
                    try:
                        prv_key_path = key_files[
                            int(input(f"Select the private key file to use (1-{len(key_files)}): ").rstrip()) - 1]
                        pub_key_path = key_files[
                            int(input(f"Select the public key file to use  (1-{len(key_files)}): ").rstrip()) - 1]

                    except Exception as e:
                        print(f"Invalid selection. Please try again. {e}")
                    else:
                        try:
                            prv_key = load_prv_pem(f"{KEYS_PATH}/{prv_key_path}")
                            pub_key = load_pub_pem(f"{KEYS_PATH}/{pub_key_path}")
                            break
                        except Exception as e:
                            print(f"Error loading selected keys: {e}.")
                            lg.error(f"Error loading selected keys: {e}")

            else:
                if "default_prv.pem" in key_files and "default_pub.pem" in key_files:
                    lg.info("Loading default encryption keys.")
                    prv_key = load_prv_pem(f"{KEYS_PATH}/default_prv.pem")
                    pub_key = load_pub_pem(f"{KEYS_PATH}/default_pub.pem")


def get_keys():
    return prv_key, pub_key
