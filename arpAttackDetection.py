from enum import Flag
from ipaddress import ip_address
from telnetlib import IP
from scapy.all import *
import scapy.layers.l2
import sys
import os
import re
import threading
import time
import netifaces

from scapy.layers.l2 import ARP

SEC = 1


# python arpAttackDetection.py
def get_arp_table():
    with os.popen('arp -a') as f:
        data = f.read()
        a = ()
    for line in re.findall('([-.0-9]+)\s+([-0-9a-f]{17})\s+(\w+)', data):
        a += line
    return a


def checkarpta(macsurce, ipmacsrc):
    table = get_arp_table()
    for i in range(len(table)):
        if ipmacsrc == table[i] and macsurce == table[i + 1]:
            return True
    return False


def sendmessage(pac):
    # change according to the case multi=False

    # pkt = Ether(dst=pac[0][ARP].hwsrc) / IP(dst=pac[0][ARP].psrc, ttl=(1, 4))
    reply = srp1((Ether(dst=pac[0][ARP].hwsrc) / IP(dst=pac[0][ARP].psrc) / ICMP()), iface="eth0", verbose=0,
                 timeout=SEC,multi=False)
    # reply = srp1(pkt, iface="eth0", verbose=0,timeout=SEC)
    if reply is None:
        return True
    return False


def detective():
    try:
        countp = 1
        while True:
            pac = sniff(count=1, lfilter=lambda r: r.haslayer(ARP) and r[ARP].op == 2)
            macsurce = str(pac[0][ARP].hwsrc)
            ipmacsrc = str(get_mac(pac[0][ARP].psrc))
            print("\r[*] Packets GOT " + str(countp), end="\n")
            countp += 1
            flagcondition1 = macsurce != ipmacsrc  # get_mac2(pac[0][ARP].psrc)
            flagcondition2 = sendmessage(pac)
            flagcondition3 = checkarpta(macsurce, ipmacsrc)
            time.sleep(SEC - 0.15)
            if (flagcondition1 and flagcondition2) or (flagcondition2 and flagcondition3):
                print(
                    "Attention you are under attack!!!\n\r" + "The mac attacker: " + macsurce + "\n\rThe found mac: " + ipmacsrc)

    except e:
        print("ERROR")


def get_mac(ip):
    # change according to the case multi=False
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=5, verbose=False,multi=False)[0]
    return answered_list[0][1].hwsrc


def get_mac2(ip):
    # change according to the case multi=True
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=5, verbose=False,multi=True)
    if len(answered_list) > 1:
        return True
    return False


def main():
    detection = threading.Thread(target=detective, args=())
    detection.start()


if __name__ == '__main__':
    main()


"""responsPacketas = AsyncSniffer(count=1,
                                       lfilter=lambda x: BOOTP in x and x[0][BOOTP].xid == transectionID and
                                                         x[0][BOOTP].op == 2, iface=i_face, timeout=2)
        responsPacketas.start()
        time.sleep(1)
        
        
           req = Ether(src=fakeMac, dst=server_mac) / IP(dst=target_ip, src="0.0.0.0") / UDP(sport=68,dport=67) / \
                      BOOTP(op=1, chaddr=fakeMac, xid=transectionID) / DHCP(options=[("message-type", "request"),
                                                                                     ("server_id", target_ip),
                                                                                     ("requested_addr",
                                                                                      responsPacketas[0][BOOTP].yiaddr),
                                                                                     "end"])
                sendp(req,iface=i_face,verbose=0)
                print("Got " + str(count) + " packets!!!")
                count +=1
        """