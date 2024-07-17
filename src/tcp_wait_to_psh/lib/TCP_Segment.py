import socket
import struct

from tcp_wait_to_psh.lib.checksum import calculate_checksum
from tcp_wait_to_psh.lib.TCP_Flags import TCP_Flags


def print_byte_string(byte_str):
    word = ""
    for byte in byte_str:
        word += "{:02x}".format(byte)
        if len(word) == 4:
            print(word)
            word = ""

class TCP_Segment():
    def __init__(
            self, src_port, dst_port, seq_num, ack_num, flags, data = b""):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.data = data

    # Python classes can only have 1 constructor
    @classmethod
    def from_bytes(klass, byte_str):
        src_port = int.from_bytes(byte_str[0:2])
        dst_port = int.from_bytes(byte_str[2:4])
        seq_num = int.from_bytes(byte_str[4:8])
        ack_num = int.from_bytes(byte_str[8:12])
        data_offset = (byte_str[12] & 0xF0) >> 4
        flags = TCP_Flags(byte_str[13])
        data = byte_str[(data_offset * 4):]
        # print_byte_string(data)
        return klass(
                src_port, dst_port, seq_num, ack_num, flags, data)

    def get_dst_port(self):
        return self.dst_port

    def get_seq_num(self):
        return self.seq_num

    def get_ack_num(self):
        return self.ack_num

    def get_flags(self):
        return self.flags

    def get_bytes(self, src_addr, dst_addr):
        # Always the same for now
        data_offset_plus_reserved_bits = 5 << 4
        window_size = 65535

        pseudo_header = socket.inet_aton(src_addr)
        pseudo_header += socket.inet_aton(dst_addr)
        pseudo_header += struct.pack(">H", 0x6)
        pseudo_header += struct.pack(">H", 20 + len(self.data))

        tcp_header_top = struct.pack(">H", self.src_port)
        tcp_header_top += struct.pack(">H", self.dst_port)
        tcp_header_top += struct.pack(">I", self.seq_num)
        tcp_header_top += struct.pack(">I", self.ack_num)
        tcp_header_top += struct.pack(">B", data_offset_plus_reserved_bits)
        tcp_header_top += struct.pack(">B", self.flags.get_integer())
        tcp_header_top += struct.pack(">H", window_size)
        # Checksum will go here
        tcp_header_urgent = struct.pack(">H", 0)

        checksum_data = self.data
        if not (len(self.data) % 2) == 0:
            checksum_data += b"\x00"

        checksum = calculate_checksum(
                pseudo_header + tcp_header_top + struct.pack(">H", 0) +
                tcp_header_urgent + checksum_data)

        return tcp_header_top + struct.pack(">H", checksum) + tcp_header_urgent + self.data

