from tcp_wait_to_psh.send import send_in_one_datagram


if __name__ == "__main__":
    print("Sending...")
    payload = b"A" * 0x1100
    payload += b"\n"
    # payload = b"Hello TCP.\n"
    send_in_one_datagram("192.168.241.10", 1234, payload)
    # send_in_one_datagram("127.0.0.1", 4444, payload)

