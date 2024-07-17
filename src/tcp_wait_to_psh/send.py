import socket

from tcp_wait_to_psh.lib.disable_auto_rst import disable
from tcp_wait_to_psh.lib.IP_Datagram import IP_Datagram
from tcp_wait_to_psh.lib.TCP_Segment import TCP_Segment
from tcp_wait_to_psh.lib.TCP_Flags import TCP_Flags



def get_response(sock, dst_port):
    while True:
        data = sock.recv(1024)
        ip_datagram = IP_Datagram.from_bytes(data)
        tcp_segment = ip_datagram.get_tcp_segment()
        if tcp_segment.get_dst_port() == dst_port:
            return ip_datagram

def establish_connection(
        sock, src_addr, dst_addr, src_port, dst_port):
    # Send Syn packet
    flags = TCP_Flags()
    flags.set_syn_flag(True)
    req_segment = TCP_Segment(src_port, dst_port, 0, 0, flags)
    req_dgram = IP_Datagram(src_addr, dst_addr, req_segment)
    sock.sendall(req_dgram.get_bytes())

    # Receive Syn-Ack
    res_dgram = get_response(sock, src_port)
    res_segment = res_dgram.get_tcp_segment()
    flags = res_segment.get_flags()
    if not flags.get_syn_flag():
        seq_num = res_segment.get_ack_num()
        ack_num = res_segment.get_seq_num()
        terminate_connection(
                sock, src_addr, dst_addr, src_port, dst_port, seq_num, ack_num)
        return establish_connection(
                sock, src_addr, dst_addr, src_port, dst_port)

    # Send Ack packet
    flags = TCP_Flags()
    flags.set_ack_flag(True)
    seq_num = res_segment.get_ack_num()
    ack_num = res_segment.get_seq_num() + 1
    req_segment = TCP_Segment(src_port, dst_port, seq_num, ack_num, flags)
    req_dgram = IP_Datagram(src_addr, dst_addr, req_segment)
    sock.sendall(req_dgram.get_bytes())

    return (seq_num, ack_num)

def terminate_connection(
        sock, src_addr, dst_addr, src_port, dst_port,
        seq_num, ack_num, fin_ack_received = False):
    if fin_ack_received:
        ack_num += 1

    # Send Fin-Ack packet
    flags = TCP_Flags()
    flags.set_fin_flag(True)
    # For some reason, closing the connection doesn't work without this
    flags.set_ack_flag(True)
    req_segment = TCP_Segment(src_port, dst_port, seq_num, ack_num, flags)
    req_dgram = IP_Datagram(src_addr, dst_addr, req_segment)
    sock.sendall(req_dgram.get_bytes())

    # Receive Fin-Ack
    res_dgram = get_response(sock, src_port)
    res_segment = res_dgram.get_tcp_segment()

    if not fin_ack_received:
        # Send Ack packet
        flags = TCP_Flags()
        flags.set_ack_flag(True)
        seq_num = res_segment.get_ack_num()
        ack_num = res_segment.get_seq_num() + 1
        req_segment = TCP_Segment(src_port, dst_port, seq_num, ack_num, flags)
        req_dgram = IP_Datagram(src_addr, dst_addr, req_segment)
        sock.sendall(req_dgram.get_bytes())

def send_in_one_datagram(dst_addr, dst_port, payload):
    src_port = 55555

    # Needed for preventing OS from resetting TCP connection
    cleanup = disable(src_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.connect((dst_addr, dst_port))
    (src_addr, _) = sock.getsockname()

    (seq_num, ack_num) = establish_connection(
            sock, src_addr, dst_addr, src_port, dst_port)

    # Send data
    flags = TCP_Flags()
    flags.set_ack_flag(True)
    flags.set_psh_flag(True)
    req_segment = TCP_Segment(
            src_port, dst_port, seq_num, ack_num, flags, payload)
    req_dgram = IP_Datagram(src_addr, dst_addr, req_segment)
    sock.sendall(req_dgram.get_bytes())

    # Receive Fin-Ack
    res_dgram = get_response(sock, src_port)
    res_segment = res_dgram.get_tcp_segment()
    seq_num = res_segment.get_ack_num()
    ack_num = res_segment.get_seq_num()

    fin_ack_received = res_segment.get_flags().get_fin_flag()

    terminate_connection(
            sock, src_addr, dst_addr, src_port, dst_port,
            seq_num, ack_num, fin_ack_received)

    sock.close()
    cleanup()

    return


