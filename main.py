import crypt_utils as cu

def main():
    prv_key = cu.generate_prv_key()
    pem_buf = cu.serialize_prv_pub_keys_to_pem(prv_key)
    cu.save_pem_to("./.keys", "default", pem_buf)

if __name__ == '__main__':
    main()
