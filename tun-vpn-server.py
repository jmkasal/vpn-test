import os
import select
import socket
import struct
from pytun import TunTapDevice
from tools.timeout_dict import TimeoutDict
from tools.ip_tools import unpack_tcp_header, unpack_ip_header, unpack_udp_header


# snippet:start xor
def xor(data: bytes, key: bytes):
    """XOR two byte arrays, repeating the key"""
    retval = bytearray(data)
    for i, _ in enumerate(data):
        retval[i] = data[i] ^ key[i % len(key)]
    return bytes(retval)
    # snippet:end xor


# snippet:start vpn
VPN_HEADER = ">4sHxx"
VPN_KEY = bytes(os.environ.get("VPN_KEY"), "utf-8")
VPN_HEADER_SIZE = struct.calcsize(VPN_HEADER)


def prepare_data_for_sending(data: bytes, key: bytes) -> bytes:
    """Encrypt and wrap data for sending via the VPN"""
    ciphertext = xor(data, key)
    return struct.pack(VPN_HEADER, VPN_KEY, len(ciphertext)) + ciphertext


def handle_received_data(data: bytes, key: bytes) -> bytes | None:
    """Unwrap and decrypt data from the VPN"""
    magic, length = struct.unpack(VPN_HEADER, data[:VPN_HEADER_SIZE])
    print(magic, VPN_KEY)
    if magic != VPN_KEY:
        return None

    ciphertext = data[VPN_HEADER_SIZE:]
    if len(ciphertext) != length:
        return None

    plaintext = xor(ciphertext, key)
    return plaintext
    # snippet:end vpn


def run(
        listen_address: tuple[str, int],
        local_ip: str,
        peer_ip: str,
        key: bytes,
):
    """Run the VPN service"""

    # Open TUN device
    tuntap = pytun.TunTapDevice(name="tun1", flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
    tuntap.mtu = 508
    tuntap.addr = local_ip
    tuntap.dstaddr = peer_ip
    tuntap.netmask = "255.255.255.0"
    tuntap.up()
    tuntap.persist(True)
    sessions = TimeoutDict(5)

    # snippet:start open_socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as remote:
            remote.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            remote.bind(listen_address)

            # snippet:end open_socket
            # snippet:start main_loop
            while True:
                rd_sockets, _, _ = select.select([tuntap, remote], [], [], 1.0)

                for sock in rd_sockets:
                    if sock is tuntap:
                        # Data from TUNTAP needs to be pumped to the peer
                        data = tuntap.read(0xFFFF)
                        src_ip, dst_ip, protocol, ip_h_len = unpack_ip_header(data)
                        if protocol == 6 or protocol == 17:
                            src_port, dst_port = (
                                unpack_tcp_header(data[ip_h_len:])
                                if protocol == 6
                                else unpack_udp_header(data[ip_h_len:])
                            )
                            # check if response is in our sessions, otherwise drop
                            peer_address = sessions.get(
                                (src_ip, dst_ip, protocol, src_port, dst_port)
                            )
                            if peer_address:
                                data = prepare_data_for_sending(data, key)
                                remote.sendto(data, peer_address)
                            else:
                                print("DROPPED PACKET")

                    elif sock is remote:
                        # Data from the peer needs to be pumped to TUNTAP
                        data, address = remote.recvfrom(0xFFFF)
                        data = handle_received_data(data, key)
                        src_ip, dst_ip, protocol, ip_h_len = unpack_ip_header(data)
                        if protocol == 6 or protocol == 17:
                            src_port, dst_port = (
                                unpack_tcp_header(data[ip_h_len:])
                                if protocol == 6
                                else unpack_udp_header(data[ip_h_len:])
                            )
                            # we want to track the response packet
                            # so when the response (hopefully) comes back, we can send it to the correct remote address
                            sessions[(dst_ip, src_ip, protocol, dst_port, src_port)] = (
                                address
                            )
                            tuntap.write(data)
                        else:
                            print(f"CANNOT HANDLE IP PROTOCOL: {protocol}")
    except Exception as e:
        print(e)
        tuntap.down()


def main(
        hex_key: str,
        local_ip: str,
        peer_ip: str,
):
    run(
        listen_address=("", 1338),
        local_ip=local_ip,
        peer_ip=peer_ip,
        key=bytes.fromhex(hex_key),
    )


if __name__ == "__main__":
    main(
        hex_key=os.environ.get("VPN_HEX_KEY"),
        local_ip="10.0.0.2",
        peer_ip="10.0.0.1",
    )
