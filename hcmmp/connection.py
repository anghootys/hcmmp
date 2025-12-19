import hashlib
import hmac
import random
import socket
from enum import Enum
from getpass import getpass

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization, hashes
import logging
from socket import *
from time import sleep

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .cryptography_utils import generate_pub_key_fingerprint, checksum_pub_key, store_fingerprint, \
    encrypt_with_rsa_pub_key, decrypt_rsa_ciphertext
from .errors import HCMMPAuthenticationFailed, HCMMPFetchHandshakeNonceFailed, HCMMPPubKeyExchangeFailed, \
    HCMMPConnectionFailed, HCMMPAESKeyRenewalFailed, HCMMPError
from .packet import HCMMPPacket, F_PUB_KEY, F_NONCE, F_AUTH
from .state import HCMMPConnectionState, get_state_title
from .consts import *

lg = logging.getLogger("HCMMP_CONNECTION")

class HCMMPHandshakeState(Enum):
    EXCHANGING_KEYS = 1
    FETCHING_NONCE = 2
    AUTHENTICATING_PASSWORD = 3
    RENEWING_AES_KEY = 4
    DONE = 5


# states:
# | -> (HCMMP Disconnected) -> (HCMMP Handshaking) -> (HCMMP Connected) -> |
class HCMMPConnection:
    def __init__(self, prv_key: RSAPrivateKey, pub_key: RSAPublicKey, adv_pkt: HCMMPPacket):
        self.__state = HCMMPConnectionState.DISCONNECTED

        self.__prv_key = prv_key
        self.__pub_key = pub_key

        self.__adv_pkt: HCMMPPacket = adv_pkt

        self.__peer_tcp_sock: socket | None = None
        self.__peer_pub_key: RSAPublicKey | None = None
        self.__peer_pub_key_fingerprint: str | None = None

        self.__handshake_nonce: bytes | None = None

        self.__peer_password: str | None = None

        self.__aes_key: bytes | None = None
        self.__iv: bytes | None = None
        self.__aes_key_tag: bytes | None = b"AES_KEY_TAG_HCMMP_V1"

    def __connect_to_peer(self):
        if self.__peer_tcp_sock is not None:
            lg.warning("Peer TCP socket is already established.")
            return True

        connection_retries = 0

        peer_tcp_sock = socket(AF_INET, SOCK_STREAM)
        peer_tcp_sock.settimeout(HCMMP_DEFAULT_TCP_TIMEOUT)

        while connection_retries < HCMMP_TCP_CONNECTION_RETRY_LIMIT:
            try:
                peer_tcp_sock.connect((self.__adv_pkt.ip, HCMMP_TCP_SERVER_PORT))

                lg.info("Connected to HCMMP server.")
                break
            except Exception as e:
                print(f"Failed to connect to HCMMP server at {self.__adv_pkt.ip}:{HCMMP_TCP_SERVER_PORT}: {e}")
                lg.error(f"Failed to connect to HCMMP server at {self.__adv_pkt.ip}:{HCMMP_TCP_SERVER_PORT}: {e}")
                connection_retries += 1
                sleep(0.5)

        if connection_retries >= HCMMP_TCP_CONNECTION_RETRY_LIMIT:
            print("Handshake retries exceeded, aborting.")
            lg.error("Exceeded maximum handshake retries, aborting.")
            return False

        peer_tcp_sock.settimeout(HCMMP_DEFAULT_TCP_TIMEOUT)
        self.__peer_tcp_sock = peer_tcp_sock

        return True

    def __handshake_exchange_pub_keys(self):
        pub_key_ex_pkt = HCMMPPacket.new(self.get_session_id(), F_PUB_KEY, b'',
                                         self.__pub_key.public_bytes(serialization.Encoding.DER,
                                                                     serialization.PublicFormat.SubjectPublicKeyInfo))

        self.__send_pkt(pub_key_ex_pkt)

        peer_pub_key_retries = 0
        while peer_pub_key_retries < 5:
            try:
                self.__peer_tcp_sock.settimeout(HCMMP_DEFAULT_TCP_TIMEOUT)
                peer_pub_key_ex_pkt = HCMMPPacket.from_bytes(self.__peer_tcp_sock)
                if peer_pub_key_ex_pkt.is_pub_key():
                    self.__peer_pub_key = serialization.load_der_public_key(peer_pub_key_ex_pkt.get_raw_data())
                    self.__peer_pub_key_fingerprint = generate_pub_key_fingerprint(self.__peer_pub_key)
                    if not checksum_pub_key(self.__adv_pkt.get_host_id(), self.__peer_pub_key_fingerprint):
                        print("!!!WARNING!!!")
                        print("Peer public key fingerprint verification failed.")
                        print(f"Peer ID: {self.__adv_pkt.get_host_id()}")
                        print(f"NEW FINGERPRINT: {self.__peer_pub_key_fingerprint.decode()}")
                        while True:
                            confirmation = input("Do you want to continue the handshake? (y/n): ").strip().lower()
                            if confirmation == 'y':
                                lg.warning("User chose to continue despite fingerprint mismatch.")
                                store_fingerprint(self.__adv_pkt.get_host_id(), self.__peer_pub_key_fingerprint)
                                break
                            elif confirmation == 'n':
                                lg.info("User aborted handshake due to fingerprint mismatch.")
                                self.reset_connection()
                                raise FingerprintVerificationFailed(
                                    "Handshake aborted by user due to fingerprint mismatch.")
                    else:
                        lg.info("Peer public key fingerprint verified successfully.")

                    break
            except FingerprintVerificationFailed:
                raise
            except Exception as e:
                lg.error(f"Could not get peer public key: {e}")
                peer_pub_key_retries += 1

        if peer_pub_key_retries >= 5:
            self.reset_connection()
            raise ConnectionResetError("Could not get peer public key.")

    def __handshake_fetch_handshake_nonce(self):
        try:
            peer_nonce_pkt = HCMMPPacket.from_bytes(self.__peer_tcp_sock)

            if not peer_nonce_pkt.is_nonce():
                raise ValueError("Received packet is not a nonce packet.")

            handshake_nonce = peer_nonce_pkt.get_raw_data()
            lg.info(f"Received nonce from peer: {int.from_bytes(handshake_nonce)}.")

            self.__handshake_nonce = handshake_nonce
        except Exception as e:
            lg.error(f"Received invalid nonce packet from peer: {e}")
            self.reset_connection()
            raise ConnectionResetError("Handshake failed due to invalid nonce packet from peer.")

    def __handshake_authenticate_password(self):
        self.__peer_tcp_sock.settimeout(HCMMP_DEFAULT_TCP_TIMEOUT)

        try:
            self.__peer_password = getpass("Enter peer password: ")

            peer_password_hash = self.__rsa_encrypt(
                hmac.new(key=self.__peer_password.encode(), msg=self.__handshake_nonce,
                         digestmod=hashlib.sha256).digest())

            auth_req_pkt = HCMMPPacket.new(self.get_host_id(), F_AUTH, b'', peer_password_hash)
            self.__send_pkt(auth_req_pkt)

            auth_res_retires = 0
            while auth_res_retires < 3:
                try:
                    auth_res_pkt = HCMMPPacket.from_bytes(self.__peer_tcp_sock)
                    if auth_res_pkt.is_auth():
                        auth_res = self.__rsa_decrypt(auth_res_pkt.get_raw_data())
                        auth_ack = hmac.new(key=b"ACK", msg=self.__handshake_nonce, digestmod=hashlib.sha256).digest()
                        if auth_res == auth_ack:
                            lg.info("Password authentication succeeded.")
                            return True
                        else:
                            return False
                    else:
                        auth_res_retires += 1
                except Exception as e:
                    lg.error(f"Could not fetch authentication result appropriately: {e}")
                    auth_res_retires += 1

            if auth_res_retires >= 3:
                lg.error("Auth response not received and retry limit exceed.")
                return False

        except Exception as e:
            lg.error(f"Password authentication failed: {e}")
            return False

    def establish_connection(self):
        try:
            self.__connect_to_peer()
        except Exception as e:
            raise HCMMPConnectionFailed(e)

    def do_handshake(self):
        if not self.__is_able_to_handshake():
            lg.warning(
                f"Connection {self.get_session_id()} is in state {self.get_curr_state_title()} and cannot do handshake.")
            return False

        self.__state = HCMMPConnectionState.HANDSHAKING
        lg.info(f"Initiating handshake with peer: {self.__adv_pkt.description()}.")

        handshake_state = HCMMPHandshakeState.EXCHANGING_KEYS
        handshake_retries = 0

        while handshake_retries < HCMMP_HANDSHAKE_RETRY_LIMIT:

            try:
                if handshake_state == HCMMPHandshakeState.EXCHANGING_KEYS:
                    try:
                        self.__handshake_exchange_pub_keys()

                        handshake_state = HCMMPHandshakeState.FETCHING_NONCE
                    except Exception as e:
                        raise HCMMPPubKeyExchangeFailed(e)

                if handshake_state == HCMMPHandshakeState.FETCHING_NONCE:
                    try:
                        self.__handshake_fetch_handshake_nonce()

                        handshake_state = HCMMPHandshakeState.AUTHENTICATING_PASSWORD
                    except Exception as e:
                        raise HCMMPFetchHandshakeNonceFailed(e)

                if handshake_state == HCMMPHandshakeState.AUTHENTICATING_PASSWORD:
                    try:
                        auth_res = self.__handshake_authenticate_password()

                        if not auth_res:
                            raise HCMMPAuthenticationFailed("Password authentication failed.")
                        handshake_state = HCMMPHandshakeState.RENEWING_AES_KEY
                    except Exception as e:
                        raise HCMMPAuthenticationFailed(e)

                if handshake_state == HCMMPHandshakeState.RENEWING_AES_KEY:
                    try:
                        self.__aes_key = self.__renewal_aes_key()

                        handshake_state = HCMMPHandshakeState.DONE
                    except Exception as e:
                        raise HCMMPAESKeyRenewalFailed(e)

                break
            except HCMMPError as e:
                handshake_retries += 1
                lg.error(f"Handshake step failed, retry {handshake_retries}...")
                if handshake_retries >= HCMMP_HANDSHAKE_RETRY_LIMIT:
                    lg.error("Exceeded maximum handshake retries, aborting.")
                    raise e
            except:
                raise


        if handshake_state == HCMMPHandshakeState.DONE:
            self.__state = HCMMPConnectionState.CONNECTED
            lg.info(f"Handshake with peer {self.get_host_id()} completed successfully.")
            return True

        return False

    def __renewal_aes_key(self):
        lg.info("Renewing AES key with peer.")

        # first exchange nonces
        lg.info("Exchanging AES nonces with peer.")
        self.__aes_nonce = random.randbytes(16)  # 128bit random byte

        aes_nonce_packet = HCMMPPacket.new(self.get_host_id(), F_NONCE, b'', self.__aes_nonce)
        self.__send_pkt(aes_nonce_packet)

        get_peer_nonce_retries = 0
        while get_peer_nonce_retries < 3:
            lg.info("Waiting for peer AES nonce.")
            try:
                peer_aes_nonce_pkt = HCMMPPacket.from_bytes(self.__peer_tcp_sock)
                if peer_aes_nonce_pkt.is_nonce():
                    self.__peer_aes_nonce = peer_aes_nonce_pkt.get_raw_data()
                    lg.info(f"Received peer AES nonce: {int.from_bytes(self.__peer_aes_nonce)}.")
                    break
            except Exception as e:
                lg.error(f"Could not get peer AES nonce: {e}")
                get_peer_nonce_retries += 1

        if get_peer_nonce_retries >= 3:
            raise Exception("Could not get peer AES nonce.")

        # derive AES key
        lg.info("Deriving AES key from exchanged nonces.")
        hkdf_aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.__aes_nonce + self.__peer_aes_nonce,
            info=self.__aes_key_tag
        )

        return hkdf_aes_key.derive(self.__peer_password.encode())

    def __rsa_encrypt(self, data: bytes) -> bytes:
        return encrypt_with_rsa_pub_key(self.__peer_pub_key, data)

    def __rsa_decrypt(self, ciphertext: bytes) -> bytes:
        return decrypt_rsa_ciphertext(self.__prv_key, ciphertext)

    def close(self):
        lg.info(f"Closing HCMMP connection {self.get_session_id()}.")
        self.reset_connection()

    def reset_connection(self):
        if self.__peer_tcp_sock is not None:
            try:
                self.__peer_tcp_sock.close()

                self.__peer_pub_key = None
                self.__peer_pub_key_fingerprint = None
            except Exception as e:
                lg.error(f"Error cleaning HCMMP connection with id {self.get_session_id()}: {e}")
            self.__peer_tcp_sock = None

        self.__state = HCMMPConnectionState.DISCONNECTED

    def is_connected(self):
        return self.__state == HCMMPConnectionState.CONNECTED and self.__peer_tcp_sock is not None

    def is_handshaking(self):
        return self.__state == HCMMPConnectionState.HANDSHAKING

    def get_host_id(self):
        return self.__adv_pkt.get_host_id()

    def get_session_id(self):
        return self.__adv_pkt.get_session_id()

    def get_curr_state_title(self):
        return get_state_title(self.__state)

    def __is_able_to_handshake(self):
        return self.__state != HCMMPConnectionState.CONNECTED

    def __send_pkt(self, pkt: HCMMPPacket):
        if not (self.is_connected() or self.is_handshaking()):
            lg.warning(f"Connection {self.get_session_id()} is not connected, cannot send packet.")
            return False

        self.__peer_tcp_sock.send(pkt.get_raw_packet())

        return True


class FingerprintVerificationFailed(Exception):
    def __init__(self, message):
        super().__init__(message)
