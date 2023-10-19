#Analyzes data from a Wireshark Capture file
#By Emanuel Gutierrez and Austin Hendricks
from scapy.all import *
from scapy.layers import *

# Read the PCAP file
packets = rdpcap('1mb_mp3_capture.pcapng')

hci_event_count = 0
l2cap_count = 0
hci_cmd_count = 0

# Iterate over the packets
for packet in packets:
    #If packet has L2CAP layer
    if packet.haslayer(scapy.layers.bluetooth.L2CAP_Hdr):
        l2cap_count += 1
    #Count other HCI events that arent 
    elif packet.haslayer(scapy.layers.bluetooth.HCI_Event_Hdr):
        hci_event_count += 1
    #Count the number of HCI_CMDs
    elif packet.haslayer(scapy.layers.bluetooth.HCI_Command_Hdr):
        hci_cmd_count += 1

print("Total number of  packets read: " + str(len(packets)))

print("Number of HCI_EVT packets: " + str(hci_event_count))
print("Number of HCI_CMD packets: " + str(hci_cmd_count))
print("Number of L2CAP packets: " + str(l2cap_count))

#Useful for quickly seeing information about a specific packet
def print_packet_info(packet):
    print(packet.layers())
    print(packet.summary())
    packet.show()
    print(packet.time)