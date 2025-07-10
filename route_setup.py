import os


def main(up=True):
    if up:
        os.system('sudo route -n add -net 10.1.1.0/24 10.0.0.1')
        os.system('netstat -rn | grep 10.1.1.0/24')
    else:
        os.system('sudo route -n delete -net 10.1.1.0/24 10.0.0.1')
        os.system('netstat -rn | grep 10.1.1.0/24')


if __name__ == '__main__':
    main()