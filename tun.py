import os
from pytun import TunTapDevice
from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.l2 import Loopback
from tools.ip_tools import unpack_ip_header, unpack_tcp_header


def set_config(tun_device: TunTapDevice, ip_1, ip_2, netmask):
    if not tun_device.name:
        raise ValueError("Device name is not set.")
    res = os.system(f"ifconfig {tun_device.name} {ip_1} {ip_2} netmask {netmask}")
    if res != 0:
        raise RuntimeError(
            f"Failed to set config for {tun_device.name}. Error code: {res}"
        )
    return res


def switch_src_dst(packet: Packet) -> Packet:
    packet[IP].src, packet[IP].dst = packet[IP].dst, packet[IP].src

    return packet


def nat(packet: Packet):
    if IP in packet:
        packet[IP].src = "192.168.1.118 "
    else:
        raise ValueError("No IP layer found in the packet.")


def dest_nat(packet: Packet, dest_ip: str, src_ip):
    if IP in packet:
        packet[IP].src = src_ip
        packet[IP].dst = dest_ip


def decr_ttl(packet: Packet) -> Packet:
    if IP in packet:
        packet[IP].ttl -= 1
        del packet[IP].chksum  # Remove checksum to force recalculation
        packet.show2()
    else:
        raise ValueError("No IP layer found in the packet.")

    return packet


def test_tun():
    tun = TunTapDevice(name="utun12")
    tun.mtu = 1500
    tun.up()
    tun.set_config("10.0.0.1", "10.0.0.2", "255.255.255.0")
    # set_config(tun, '10.1.1.1', '10.1.1.2', '255.255.255.0')
    while True:
        try:
            data = tun.read(1500)[4:]
            if not data:
                continue
            pkt = Loopback(data)
            print(f"Received packet: {pkt.summary()} of length: {len(data)}")
            src_ip, dst_ip, protocol, ip_h_len = unpack_ip_header(data)
            if protocol == 6:
                src_port, dst_port = unpack_tcp_header(data[ip_h_len:])

            dec = input("Forward packet? (y/n): ")
            if dec.lower() != "y":
                print("Packet dropped.")
                continue

        except KeyboardInterrupt:
            print("Exiting...")
            break
    tun.down()


def main():
    test_tun()


if __name__ == "__main__":
    main()
