import os
from scapy.all import sniff


def test_scapy():
    sniff(prn=lambda x: x.show(), store=0, iface='utun4')


def main():

    test_scapy()



if __name__ == '__main__':
    main()