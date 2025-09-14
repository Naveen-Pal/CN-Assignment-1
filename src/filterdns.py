from scapy.all import rdpcap, wrpcap, DNS, UDP

# Read the original capture file
packets = rdpcap("dns.pcap")

# Filter only DNS queries
dns_queries = []
for pkt in packets:
    if pkt.haslayer(DNS) and pkt.haslayer(UDP):
        # Only include DNS *queries* (QR=0 means query, QR=1 means response)
        if pkt[DNS].qr == 0:
            dns_queries.append(pkt)

# Save filtered packets into a new pcap file
wrpcap("dns_queries.pcap", dns_queries)

print(f"Saved {len(dns_queries)} DNS queries to dns_queries.pcap")
