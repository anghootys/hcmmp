# Health Care Monitor Management Protocol (HCMMP)
# HCMMP Packet Specification Module
# <--------------32bit-------------->
# |               ID                |
# |---------------------------------|
# | flg | hdr_len |    data len     |
# |---------------------------------|
# |             Options             |
# |---------------------------------|
# |               Data              |
# |---------------------------------|
#

from socket import socket
import struct

F_ADVERTISEMENT = 1 << 0
F_PUB_KEY = 1 << 1
F_NONCE = 1 << 2
F_AUTH = 1 << 3
F_DATA = 1 << 4

SAMPLE_SIZE = 4 # 4bytes RED, 4bytes IR, 4bytes Timestamp


class HCMMPPacket:
    def __init__(
        self,
        ip,
        port,
        host_id: int,
        flags: int,
        header_length: int,
        data_length: int,
        options: bytes,
        data: bytes,
    ):
        self.ip = ip
        self.port = port
        self.host_id = host_id
        self.flags = flags
        self.header_length = header_length
        self.data_length = data_length

        self.session_id = 0

        self.options = options if options else b""
        self.data = data if data else b""

    @staticmethod
    def new(host_id: int, flags: int, options: bytes, data: bytes):
        if not options:
            options = b""

        if not data:
            data = b""

        return HCMMPPacket(
            None, None, host_id, flags, 8 + len(options), len(data), options, data
        )

    @staticmethod
    def from_bytes(sock: socket):
        pkt_hdr = sock.recvfrom(8)
        pkt_data = [b"", ("", 0)]

        hdr_len, data_len = get_pkt_len(pkt_hdr[0])
        if hdr_len > 8:
            hdr_opts = sock.recvfrom(hdr_len - 8)
            pkt_hdr[0] += hdr_opts[0]

        if data_len > 0:
            pkt_data = sock.recvfrom(data_len)

        return parse_hcmmp_packet(pkt_hdr[0] + pkt_data[0], pkt_hdr[1])

    def get_host_id(self):
        return self.host_id

    def get_session_id(self):
        return self.session_id

    def get_raw_packet(self):
        return struct.pack(
            f"!IBBH{len(self.options)}s{len(self.data)}s",
            self.host_id,
            self.flags,
            self.header_length,
            self.data_length,
            self.options,
            self.data,
        )

    def get_raw_data(self):
        return self.data

    def get_sample(self):
        pkt_sample_counts = len(self.data) // SAMPLE_SIZE
        for i in range(pkt_sample_counts):
            offset = i * SAMPLE_SIZE

            sample_raw = self.data[offset:offset + SAMPLE_SIZE]

            if len(sample_raw) != SAMPLE_SIZE:
                raise ValueError("Size of sensor sample is not valid")



    def description(self):
        return f"{self.host_id} - {self.ip}:{self.port}"

    def is_advertisement(self):
        return self.flags & F_ADVERTISEMENT != 0

    def is_pub_key(self):
        return self.flags & F_PUB_KEY != 0

    def is_nonce(self):
        return self.flags & F_NONCE != 0

    def is_auth(self):
        return self.flags & F_AUTH != 0

    def is_data(self):
        return self.flags & F_DATA != 0


def get_pkt_len(hdr_bytes: bytes):
    if len(hdr_bytes) < 8:
        raise ValueError("Header bytes too short to determine packet length.")

    header_length = hdr_bytes[5]
    data_length = int.from_bytes(hdr_bytes[6:8], byteorder="big")

    return header_length, data_length


def parse_hcmmp_packet(packet_bytes: bytes, sender_addr) -> HCMMPPacket:
    if len(packet_bytes) < 8:
        raise ValueError("Packet too short to be a valid HCMMP packet.")

    packet_id, flags, header_length, data_length = struct.unpack(
        "!IBBH", packet_bytes[:8]
    )

    if len(packet_bytes) < header_length + data_length:
        raise ValueError("Packet length does not match header and data lengths.")

    options = None
    data = None

    if header_length > 8:
        options = packet_bytes[8:header_length]

    if data_length > 0:
        data = packet_bytes[header_length : header_length + data_length]

    if sender_addr is None or len(sender_addr) != 2:
        return HCMMPPacket(
            None, None, packet_id, flags, header_length, data_length, options, data
        )
    else:
        return HCMMPPacket(
            sender_addr[0],
            sender_addr[1],
            packet_id,
            flags,
            header_length,
            data_length,
            options,
            data,
        )
