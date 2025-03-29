import os
from pytun import TunTapDevice
from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.l2 import Loopback
from scapy.all import send


def set_config(tun_device: TunTapDevice, ip_1, ip_2, netmask):
    if not tun_device.name:
        raise ValueError("Device name is not set.")
    res = os.system(f"ifconfig {tun_device.name} {ip_1} {ip_2} netmask {netmask}")
    if res != 0:
        raise RuntimeError(f"Failed to set config for {tun_device.name}. Error code: {res}")
    return res


def switch_src_dst(packet: Packet) -> Packet:
    packet[IP].src, packet[IP].dst = packet[IP].dst, packet[IP].src

    return packet


def nat(packet: Packet):
    if IP in packet:
        packet[IP].src = '192.168.1.118 '
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


def main():

    tun = TunTapDevice(name='utun5')
    tun.mtu = 1500
    tun.up()
    tun.set_config('10.1.1.1', '10.1.1.2', '255.255.255.0')
    # set_config(tun, '10.1.1.1', '10.1.1.2', '255.255.255.0')
    while True:
        try:
            data = tun.read(1500)
            if not data:
                continue
            pkt = Loopback(data)
            print(f"Received packet: {pkt.summary()}")
            dest_nat(pkt, '8.8.8.8', '10.1.1.2')
            decr_ttl(pkt)
            dec = input('Forward packet? (y/n): ')
            if dec.lower() != 'y':
                print("Packet dropped.")
                continue
            tun.write(bytes(pkt))

        except KeyboardInterrupt:
            print("Exiting...")
            break
    tun.down()



if __name__ == '__main__':
    main()