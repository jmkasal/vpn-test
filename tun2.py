import os
from scapy.all import sniff


def test_scapy():
    sniff(prn=lambda x: x.show(), store=0, filter='tcp port 80', iface='utun5')


def main():

    test_scapy()



if __name__ == '__main__':
    main()