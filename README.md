# Tool99
ARP and DNS Spoofing Tool

Welcome to the ARP and DNS Spoofing Tool of Team 99. This tool was made for 2IC80 - Lab on Offensive Computer Security.

The tool is able to perform an ARP Spoofing attack between two given IPs. If desired, the DNS Spoofing attack feature can be enabled.

To start the tool, enter the following command in a linux terminal:<br>
sudo python tool.py \<network> <br>
\<network> represents the network on which the attack is performed. 
  
After the tool starts, an nmap is performed to see the available hosts on the network. Then, you have to input the IPs and then you can choose which features you want to enable. (MiTM and/or DNS Spoofing). 

To see the sniffed communication between the two IPs, you will need a packet sniffer tool (e.g. wireshark). 

To close the tool, you have to press from keyboard CTRL+C. 
