import random
import socket
import struct

from tcp_wait_to_psh.lib.checksum import calculate_checksum
from tcp_wait_to_psh.lib.TCP_Segment import TCP_Segment


class IP_Datagram():
    def __init__(self, src_addr, dst_addr, tcp_segment):
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.tcp_segment = tcp_segment

    @classmethod
    def from_bytes(klass, byte_str):
        version = (byte_str[0] & 0xF0) >> 4
        IHL = (byte_str[0] & 0xF)
        total_length = int.from_bytes(byte_str[2:4])
        src_addr = int.from_bytes(byte_str[12:16])
        dst_addr = int.from_bytes(byte_str[16:20])
        tcp_segment = TCP_Segment.from_bytes(byte_str[(IHL * 4):])
        return klass(src_addr, dst_addr, tcp_segment)

    def get_tcp_segment(self):
        return self.tcp_segment

    def get_bytes(self):
        # Version and IHL
        version = 4
        IHL = 5
        ip_header_top = struct.pack(">B", (version << 4) + IHL)
        
        # DSCP and ECN
        ip_header_top += struct.pack(">B", 0)

        # Total Length
        tcp_byte_str = self.tcp_segment.get_bytes(self.src_addr, self.dst_addr)
        ip_header_top += struct.pack(">H", (IHL * 5) + len(tcp_byte_str))

        # Identification
        ip_header_top += random.randbytes(2)

        # Flags and offset
        ip_header_top += struct.pack(">H", 0)

        # Time to live
        ip_header_top += struct.pack(">B", 0x40)

        # Protocol
        ip_header_top += struct.pack(">B", 6)

        # Checksum would go here

        # Source address
        ip_header_addrs = socket.inet_aton(self.src_addr)

        # Destination address
        ip_header_addrs += socket.inet_aton(self.dst_addr)

        checksum = calculate_checksum(
                ip_header_top + struct.pack(">H", 0) + ip_header_addrs)
        ip_header = ip_header_top + struct.pack(">H", checksum) + ip_header_addrs

        return ip_header + tcp_byte_str


