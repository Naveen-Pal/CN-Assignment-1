from scapy.all import rdpcap, wrpcap, DNS, UDP
from datetime import datetime

# Read packets
packets = rdpcap("dns_queries.pcap")

dns_queries = []
query_count = 0

for pkt in packets:
    # Get timestamp in HHMMSS
    ts = datetime.now().strftime("%H%M%S")

    # ID = two digits (00, 01, 02, ...)
    seq_id = f"{query_count:02d}"

    # Build custom header (8 bytes string)
    custom_header = (ts + seq_id).encode("utf-8")
    print(custom_header)

    # Raw DNS packet bytes
    raw_dns = bytes(pkt[DNS])

    # Prepend custom header
    modified_payload = custom_header + raw_dns

    # Replace original UDP payload with new payload
    pkt[UDP].remove_payload()
    pkt[UDP].add_payload(modified_payload)

    # Recalculate lengths & checksums
    del pkt[UDP].len
    del pkt[UDP].chksum

    dns_queries.append(pkt)
    query_count = (query_count+1)

# Save modified DNS queries into a new file
wrpcap("dns_custom_header.pcap", dns_queries)

print(f"Saved {len(dns_queries)} DNS queries with custom header.")
