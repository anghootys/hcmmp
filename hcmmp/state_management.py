from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
import logging
from socket import *
import sys

from hcmmp.connection import HCMMPConnection, FingerprintVerificationFailed
from hcmmp.consts import *
from hcmmp.errors import HCMMPConnectionFailed
from hcmmp.packet import HCMMPPacket

lg = logging.getLogger("HCMMP")


HCMMP_DISCONNECTED = 0x0A
HCMMP_HANDSHAKING = 0x0C
HCMMP_CONNECTED = 0x0D


class HCMMPMessage:
    def __init__(self, data: bytes):
        self.__data = data


def scan_HCMMP_broadcast():
    hcmmp_adv_list = []

    is_first_print = True
    last_hcmmp_broadcast_count = 0

    def print_broadcast_clients():
        nonlocal is_first_print, last_hcmmp_broadcast_count

        if not is_first_print:
            for _ in range(last_hcmmp_broadcast_count + 4):
                sys.stdout.write("\033[2K")
                sys.stdout.write("\033[1A")
            sys.stdout.write("\033[2K")
            sys.stdout.flush()

        is_first_print = False
        last_hcmmp_broadcast_count = len(hcmmp_adv_list)

        tbl_hdr = f"{'#':^5} | {'ID - IP Address:Port':^30}"
        print(tbl_hdr)
        print("-" * len(tbl_hdr))

        for i, pkt in enumerate(hcmmp_adv_list):
            print(f"{i + 1:^5} | {pkt.description():^30}")

        print("\nCtrl+C to stop scanning.")

    with socket(AF_INET, SOCK_DGRAM) as usfd:
        usfd.bind(('', HCMMP_BROADCAST_PORT))

        while True:
            usfd.settimeout(1)
            print_broadcast_clients()

            try:
                hcmmp_pkt = HCMMPPacket.from_bytes(usfd)
                if hcmmp_pkt.is_advertisement() and hcmmp_pkt.get_session_id() not in map(lambda x: x.get_session_id(), hcmmp_adv_list):
                    hcmmp_adv_list.append(hcmmp_pkt)
            except ValueError as e:
                lg.warning(f"Received invalid HCMMP packet: {e}")
            except TimeoutError:
                continue
            except KeyboardInterrupt:
                sys.stdout.write('\n')
                sys.stdout.flush()
                break

    while True:
        try:
            return hcmmp_adv_list[int(input("Enter the number of the client to connect to: ")) - 1]
        except Exception:
            print("Invalid input.")


def handle_HCMMP(prv_key: RSAPrivateKey, pub_key: RSAPublicKey):
    hcmmp_connection = None

    while hcmmp_connection is None:
        lg.info("Scanning for HCMMP broadcasts...")
        try:
            hcmmp_adv_pkt = scan_HCMMP_broadcast()
            lg.info(f"Found HCMMP advertisement from {hcmmp_adv_pkt.description()}")

            hcmmp_connection = HCMMPConnection(prv_key, pub_key, hcmmp_adv_pkt)
        except Exception as e:
            print("scanning failed, check logs for more information.")
            lg.error(f"HCMMP scanning broadcast advertisements failed: {e}")

    if hcmmp_connection is None:
        return

    connection_establishment_retries = 0
    while connection_establishment_retries < HCMMP_TCP_CONNECTION_RETRY_LIMIT:
        try:
            hcmmp_connection.establish_connection()
            break
        except Exception as e:
            lg.error(f"Failed to establish HCMMP TCP connection: {e}")
            connection_establishment_retries += 1
            if connection_establishment_retries >= HCMMP_TCP_CONNECTION_RETRY_LIMIT:
                lg.error("Reached maximum TCP connection retry limit. Aborting HCMMP handling.")
                raise HCMMPConnectionFailed(e)

    handshake_retries = 0
    while handshake_retries < HCMMP_HANDSHAKE_RETRY_LIMIT:
        try:
            lg.info("Starting HCMMP handshake...")
            handshake_result = hcmmp_connection.do_handshake()

            if not handshake_result:
                lg.error("HCMMP handshake failed.")
                hcmmp_connection.close()
                handshake_retries += 1
                continue

            lg.info("HCMMP handshake completed successfully.")
            break
        except ConnectionResetError:
            lg.error("Connection was reset by peer during handshake.")
            continue
        except KeyboardInterrupt:
            lg.info("HCMMP handler interrupted by user.")
            hcmmp_connection.close()
            return
        except FingerprintVerificationFailed as e:
            lg.error(f"Fingerprint verification failed: {e}")
            hcmmp_connection.close()
            raise

    if handshake_retries >= HCMMP_HANDSHAKE_RETRY_LIMIT:
        lg.error("Reached maximum handshake retry limit. Aborting HCMMP handling.")
        raise HCMMPConnectionFailed("Handshake failed after maximum retries.")

    lg.info("HCMMP connection established and authenticated successfully.")

    hcmmp_connection.close()
