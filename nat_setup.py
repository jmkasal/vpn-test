import os


def main(interface_names: list[str]):
    for if_name in interface_names:
        os.system(f'iptables -t nat -A POSTROUTING -o {if_name} -j MASQUERADE')


if __name__ == '__main__':
    main(['eth0'])
