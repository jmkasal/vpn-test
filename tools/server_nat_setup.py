import os


def main(interface_name, tun_name):
    os.system(f"iptables -t nat -A POSTROUTING -o {interface_name} -j MASQUERADE")
    os.system(f"iptables -A FORWARD -s 10.0.0.0/24 -i {tun_name} -j ACCEPT")
    os.system(f"iptables -A FORWARD -d 10.0.0.0/24 -i {interface_name}")


if __name__ == "__main__":
    main(["enX0"])
