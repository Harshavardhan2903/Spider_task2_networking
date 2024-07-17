
'''from scapy.all import *


packet = IP(src = '102.7.8.6' , dst = '8.8.8.8')/ICMP()

sr1(packet,timeout=5,verbose=False)

newpacket = Ether()/IP()/UDP()
newpacket.show()

sniff()

from scapy.all import sniff

def packet_callback(packet):
    print(packet.show())

sniff(prn=packet_callback, count=10,iface="Wi-Fi")'''

from scapy.all import *

def packet_callback(packet):
    # Check if the packet has Ethernet layer
    if packet.haslayer(Ether):
        eth_layer = packet.getlayer(Ether)
        src_mac = eth_layer.src
        dst_mac = eth_layer.dst
    else:
        src_mac = "N/A"
        dst_mac = "N/A"

    # Check if the packet has IP layer
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    else:
        src_ip = "N/A"
        dst_ip = "N/A"

    # Determine the Layer 4 protocol
    if packet.haslayer(TCP):
        protocol = "TCP"
        l4_layer = packet.getlayer(TCP)
        src_port = l4_layer.sport
        dst_port = l4_layer.dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        l4_layer = packet.getlayer(UDP)
        src_port = l4_layer.sport
        dst_port = l4_layer.dport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        src_port = "N/A"
        dst_port = "N/A"
    else:
        protocol = "Other"
        src_port = "N/A"
        dst_port = "N/A"

    # Print packet details
    print(f"Protocol: {protocol}")
    print(f"Source MAC: {src_mac} -> Destination MAC: {dst_mac}")
    print(f"Source IP: {src_ip} -> Destination IP: {dst_ip}")
    print(f"Source Port: {src_port} -> Destination Port: {dst_port}")
    print("="*50)

# Capture packets and apply the callback function
sniff(prn=packet_callback, store=0 , count = 30 , iface="Wi-Fi")

