# ARP-Spoofing-Attack
## What is arp spoofer attack
ARP spoofing is a type of attack in which a malicious actor sends falsified ARP (Address Resolution Protocol) messages over a local area network. This results in the linking of an attacker's MAC address with the IP address of a legitimate computer or server on the network.
![arp2](https://user-images.githubusercontent.com/72939664/164459040-e24ad396-16ce-46fe-b5f3-c56386d9184b.png)

## How it's work 
In my code the attacker send infinity arp replay on lagel to the victim. As a result, the vicitm change on his arp table the lagel IP and connect it to the mac of the attacker, so now happening man in the middle and all the message that the victim want to send for the under attack IP it's send to the attacker.

## Demonstration
#### There are two VM the right is the attacker and the left is the victim
![arp1](https://user-images.githubusercontent.com/72939664/164455115-fadf52c0-31a5-4bff-8392-656d3c61716a.png)

#### Now let's begin the attack
![arp3](https://user-images.githubusercontent.com/72939664/164459252-e8d37352-06dc-42c1-857b-68d01786ae6e.png)

#### We can see for the attack work for two diffrent IP there same mac address
![arp4](https://user-images.githubusercontent.com/72939664/164459509-a3fbb074-57dc-44ae-80a7-f70028764652.png)
