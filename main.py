import datetime
import logging
from os import mkdir
from os.path import isdir

from crypt_mng import handle_encryption_keys, get_keys
from hcmmp import handle_HCMMP

TAG = "MAIN"

LOGS_PATH = "./logs"


def init_logging():
    if not isdir(LOGS_PATH):
        mkdir(LOGS_PATH)

    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(asctime)s][%(name)s] - %(levelname)s: %(message)s',
        filename=f"{LOGS_PATH}/app-{datetime.datetime.now().strftime('%d-%m-%y')}.txt",
        filemode='a',
    )


def main():
    init_logging()
    lg = logging.getLogger(TAG)
    lg.info("Logger initialized.")

    try:
        lg.info("Generate/Load encryption keys.")
        handle_encryption_keys()
        lg.info("Encryption keys are ready.")
    except KeyboardInterrupt:
        print("Encryption key handling interrupted by user. It is required for application to run.")
        lg.info("Encryption keys handling Interrupted by user.")
        exit(0)
    except Exception as e:
        lg.error(f"Error while handling encryption keys: {e}")
        print("Error while handling encryption keys. Check logs for details.")
        exit(1)

    try:
        handle_HCMMP(*get_keys())
    except KeyboardInterrupt:
        lg.error("HCMMP handling interrupted by user.")
        exit(0)
    except Exception as e:
        lg.error(f"Could not handle HCMMP: {e}")
        exit(1)


if __name__ == '__main__':
    main()
