import random
from socket import *
import struct
from time import sleep

from hcmmp.state_management import HCMMP_BROADCAST_PORT


def main():
    with socket(AF_INET, SOCK_DGRAM) as udp_sock:
        while True:
            pkt_header = struct.pack("!IBBH", random.randint(10, 20), 0b00000000, 8, 0)  # ID=1, flags=0, header_length=8, data_length=0
            udp_sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
            udp_sock.sendto(pkt_header, ('255.255.255.255', HCMMP_BROADCAST_PORT))
            print(f"snt: {pkt_header.hex()}")
            sleep(1)


main()