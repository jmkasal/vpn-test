import struct

# Example IP header bytes (simplified for demonstration)

# Format string for unpacking (e.g., Version/IHL, TOS, Total Length, ID, Flags/Frag Offset, TTL, Protocol, Checksum, Source IP, Dest IP)
# '>BBHHHBBHII' - Big-endian, 2 unsigned bytes, 3 unsigned shorts, 2 unsigned bytes, 1 unsigned short, 2 unsigned ints
# Note: This is a simplified example and might not perfectly match all IP header fields.
IP_FORMAT_STRING = ">BHHHBBHII"
TCP_FORMAT_STRING = ">HH"


# Unpacking the IP header bytes
def unpack_ip_header(data: bytes):
    ihl = data[0]
    version = ihl >> 4
    if version == 6:
        return None, None, None, None
    internet_header_length = ((ihl & 0xF) * 32) // 8
    ip_header = data[1:internet_header_length]
    (
        tos,
        total_length,
        identification,
        flags_frag_offset,
        ttl,
        protocol,
        header_checksum,
        src_ip_raw,
        dest_ip_raw,
    ) = struct.unpack(IP_FORMAT_STRING, ip_header)
    src_ip = f"{(src_ip_raw >> 24) & 0xFF}.{(src_ip_raw >> 16) & 0xFF}.{(src_ip_raw >> 8) & 0xFF}.{src_ip_raw & 0xFF}"
    dest_ip = f"{(dest_ip_raw >> 24) & 0xFF}.{(dest_ip_raw >> 16) & 0xFF}.{(dest_ip_raw >> 8) & 0xFF}.{dest_ip_raw & 0xFF}"
    return (src_ip, dest_ip, protocol, internet_header_length)


def unpack_tcp_header(data: bytes):
    (src_port, dest_port) = struct.unpack(TCP_FORMAT_STRING, data[:4])
    print(f"source port: {src_port}")
    print(f"dest port: {dest_port}")
    return src_port, dest_port


def unpack_udp_header(data: bytes):
    (src_port, dest_port) = struct.unpack(TCP_FORMAT_STRING, data[:4])
    print(f"source port: {src_port}")
    print(f"dest port: {dest_port}")
    return src_port, dest_port


def main():
    ip_header_bytes = b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x7c\xb9\xc0\xa8\x01\x01\xc0\xa8\x01\x02"
    unpack_ip_header(ip_header_bytes)


if __name__ == "__main__":
    main()
