from scapy.all import *
from scapy.layers import *
from matplotlib import pyplot as plt
def print_packet_info(packet):
    print(packet.layers())
    print(packet.summary())
    packet.show()
    print(packet.time)

# Read the PCAP file
packets = rdpcap('controls_cap2.pcapng')

hci_event_count = 0
l2cap_count = 0
hci_cmd_count = 0
rfcomm_count = 0

l2_cap_times =[]
hci_evt_times =[]

l2_cap_totals = []
hci_evt_totals = []

initial_time = packets[0].time

# Iterate over the packets
for packet in packets:
    #If packet has L2CAP layer
    if packet.haslayer(scapy.layers.bluetooth.L2CAP_Hdr):
        l2cap_count += 1
        l2_cap_totals.append(l2cap_count)
        l2_cap_times.append(packet.time - initial_time)
    #Count other HCI events that arent 
    elif packet.haslayer(scapy.layers.bluetooth.HCI_Event_Hdr):
        hci_event_count += 1
        hci_evt_totals.append(hci_event_count)
        hci_evt_times.append(packet.time - initial_time)
    #Count the number of HCI_CMDs
    elif packet.haslayer(scapy.layers.bluetooth.HCI_Command_Hdr):
        hci_cmd_count += 1
    if packet.haslayer(scapy.layers.bluetooth.BluetoothRFCommSocket):
        rfcomm_count += 1
print("Total number of  packets read: " + str(len(packets)))

print("Number of HCI_EVT packets: " + str(hci_event_count))
print("Number of HCI_CMD packets: " + str(hci_cmd_count))
print("Number of L2CAP packets: " + str(l2cap_count))
print("Number of RFCOMM packets: " + str(rfcomm_count))
print(packets[-1].layers)
plt.plot(l2_cap_times, l2_cap_totals)
plt.plot(hci_evt_times, hci_evt_totals)
plt.xlabel("Time since capture (Seconds)")
plt.ylabel("Number of packets received")
plt.legend(["L2CAP", "HCI_EVT"])
plt.show()

#Useful for quickly seeing information about a specific packet
