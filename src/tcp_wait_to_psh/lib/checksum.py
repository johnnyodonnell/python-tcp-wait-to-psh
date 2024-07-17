
def carry_over(value):
    top_bits = value >> 16
    while top_bits > 0:
        value = (value & 0xFFFF) + top_bits
        top_bits = value >> 16
    return value

# Received help from:
# - https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
# - https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/
def calculate_checksum(byte_str):
    total = 0
    for i in range(0, len(byte_str), 2):
        value = int.from_bytes(byte_str[i:i+2])
        total += value

    return 0xFFFF - carry_over(total)

