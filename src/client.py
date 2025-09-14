import socket
import csv
from scapy.all import rdpcap, UDP, DNS

# Read packets from modified pcap (with custom header prepended)
packets = rdpcap("dns_custom_header.pcap")

# UDP socket (client)
server_addr = ("127.0.0.1", 5359)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("Custom Header", "Domain Name", "Resolved Ip")

# Prepare CSV file
csv_filename = "dns_results.csv"
csv_data = [["Custom Header", "Domain Name", "Resolved Ip"]]  # Header row

for i, pkt in enumerate(packets):
    if pkt.haslayer(UDP):
        # Extract payload (custom header + DNS query)
        payload = bytes(pkt[UDP].payload)

        # Send packet
        sock.sendto(payload, server_addr)

        # Receive response
        try:
            resp, _ = sock.recvfrom(2048)
            custom_header = resp[:8].decode(errors="ignore")
            dns_bytes = resp[8:]
            dns_pkt = DNS(dns_bytes)
            
            # Extract domain name from the query
            domain_name = dns_pkt.qd.qname.decode() if dns_pkt.qd else "Unknown"
            
            # Extract resolved IP address from the answer section
            resolved_ip = "None"
            if dns_pkt.an and dns_pkt.an.rdata:
                resolved_ip = dns_pkt.an.rdata

            # Add row to the table
            print(custom_header, domain_name, resolved_ip)
            
            # Add to CSV data
            csv_data.append([custom_header, domain_name, resolved_ip])

        except socket.timeout:
            print(f"    ✗ No response received for packet {i} (timeout)")

# Write collected data to CSV file
with open(csv_filename, 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerows(csv_data)
    
print(f"\nTable data saved to {csv_filename}")
