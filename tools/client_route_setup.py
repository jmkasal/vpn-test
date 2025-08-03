import os


def main(up=True):
    if up:
        os.system("sudo route -n add -net 0.0.0.0/1 10.0.0.1")
        os.system("sudo route -n add -net 128.0.0.0/1 10.0.0.1")
        os.system("sudo route -n add -net 44.211.159.105/32 192.168.1.204")

        # os.system("sudo route -n add -net 8.8.8.8/32 10.0.0.1")
        # os.system("sudo route -n add -net 104.26.12.23/32 10.0.0.1")
        # os.system("sudo route -n add -net 172.67.69.129/32 10.0.0.1")
        # os.system("sudo route -n add -net 104.26.13.23/32 10.0.0.1")

        os.system("netstat -rn | grep 10.1.1.0/24")
    else:
        os.system("sudo route -n delete -net 10.1.1.0/24 10.0.0.1")
        os.system("sudo route -n delete -net 8.8.8.8/32 10.0.0.1")
        os.system("netstat -rn | grep 10.1.1.0/24")


if __name__ == "__main__":
    main()
