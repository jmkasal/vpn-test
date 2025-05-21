
import select
import socket
import struct
from pytun import TunTapDevice

# snippet:start xor
def xor(data: bytes, key: bytes):
    """XOR two byte arrays, repeating the key"""
    retval = bytearray(data)
    for i, _ in enumerate(data):
        retval[i] = data[i] ^ key[i % len(key)]
    return bytes(retval)
    # snippet:end xor


# snippet:start vpn
CRAPVPN_HEADER = ">4sHxx"
CRAPVPN_MAGIC = b"crap"
CRAPVPN_HEADER_SIZE = struct.calcsize(CRAPVPN_HEADER)


def prepare_data_for_sending(data: bytes, key: bytes) -> bytes:
    """Encrypt and wrap data for sending via the VPN"""
    ciphertext = xor(data, key)
    return struct.pack(CRAPVPN_HEADER, CRAPVPN_MAGIC, len(ciphertext)) + ciphertext


def handle_received_data(data: bytes, key: bytes) -> bytes | None:
    """Unwrap and decrypt data from the VPN"""
    magic, length = struct.unpack(CRAPVPN_HEADER, data[:CRAPVPN_HEADER_SIZE])

    if magic != CRAPVPN_MAGIC:
        return None

    ciphertext = data[CRAPVPN_HEADER_SIZE:]
    if len(ciphertext) != length:
        return None

    plaintext = xor(ciphertext, key)
    return plaintext
    # snippet:end vpn


def run(
    listen_address: tuple[str, int],
    local_ip: str,
    peer_address: tuple[str, int],
    peer_ip: str,
    key: bytes,
):
    """Run the VPN service"""

    # Open TUN device
    device_name = "tun0"
    tuntap = TunTapDevice(name='utun12')
    tuntap.mtu = 1500
    tuntap.up()
    tuntap.set_config(local_ip, peer_ip, '255.255.255.0')


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
                        data = prepare_data_for_sending(data, key)
                        remote.sendto(data, peer_address)

                    elif sock is remote:
                        # Data from the peer needs to be pumped to TUNTAP
                        data = remote.recv(0xFFFF)
                        data = handle_received_data(data, key)
                        print(data)
                        if data:
                            tuntap.write(data)
    except Exception as e:
        print(e)
        tuntap.down()


def main(
    hex_key: str,
    peer_host: str,
    local_ip: str,
    peer_ip: str,
):

    run(
        listen_address=("", 1337),
        peer_address=(peer_host, 1337),
        local_ip=local_ip,
        peer_ip=peer_ip,
        key=bytes.fromhex(hex_key),
    )


if __name__ == "__main__":
    main(hex_key='1234', peer_host='52.90.76.130', local_ip='10.0.0.1', peer_ip='10.0.0.2')
