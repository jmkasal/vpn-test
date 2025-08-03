import os


def main(interface_names: list[str]):
    for if_name in interface_names:
        os.system(f'iptables -t nat -A POSTROUTING -o {if_name} -j MASQUERADE')
    os.system('iptables -A FORWARD -s 10.0.0.0/24 -i tun1 -j ACCEPT')
    os.system('iptables -A FORWARD -d 10.0.0.0/24 -i enX0 -j ACCEPT')



if __name__ == '__main__':
    main(['eth0'])
