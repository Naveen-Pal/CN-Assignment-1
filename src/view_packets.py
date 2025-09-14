from scapy.all import rdpcap

# Load packets from a .pcap file
packets = rdpcap("dns_queries.pcap")

# Print summary of packets
packets.summary()
# packets[0].show()
print(packets[0]["UDP"].show2(dump=True))