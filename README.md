# Detection-ARP-Spoofing-Attack

> Detection for the arp attack that I write
> action to detect the arp attack

## In the code we use three methods to find if we are under arp spoofing attack

The main idea is to keep sniffing packets (passive monitoring or scanning) in the network, once an ARP packet is received, we analyze it and use those methods:


     1.  The source MAC address (that can be spoofed).
     The real MAC address of the sender (we can easily get it by initiating an ARP request of the source IP address).
     And then we compare the two. If they are not the same, then we are definitely under an ARP spoof attack!
     
     2. Send echo requset to the IP and mac address thet we got on the arp replay and check if we don't get only one echo replay the arp replay we got is suspicious.
     
     3. Check if the same IP and mac appear on the arp table if not is suspicious.(it's stupid but we must use three methods😑😑😑).
    
If we got at least two problems from our methods the arp replay is suspicious and we send warn.

## 
