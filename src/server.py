import socket
import json
from datetime import datetime
from dnslib import DNSRecord, QTYPE, RR, A

# IP pool
IP_POOL = [
    "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
    "192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10",
    "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

def get_time_period(hour: int):
    """Decide time period (morning, afternoon, night) and return rule configuration."""
    RULES = {
        "morning": {"ip_pool_start": 0, "hash_mod": 5},
        "afternoon": {"ip_pool_start": 5, "hash_mod": 5},
        "night": {"ip_pool_start": 10, "hash_mod": 5}
    }
    if hour>=20:
        return RULES["night"]
    if hour>=12:
        return RULES["afternoon"]
    if hour>=4:
        return RULES["morning"]
    else:
        return RULES["night"]

def resolve_ip(header: str):
    """Pick IP from pool based on header and rules."""
    hh = int(header[:2])
    session_id = int(header[6:])  # last two digits

    rule = get_time_period(hh)
    ip_pool_start = rule["ip_pool_start"]
    hash_mod = rule["hash_mod"]

    idx = ip_pool_start + (session_id % hash_mod)
    return IP_POOL[idx]

def start_dns_server(host="0.0.0.0", port=5359):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"[+] Custom DNS server running on {host}:{port}")

    try:
        while True:
            data, addr = sock.recvfrom(2048)

            # Extract custom header (8 bytes) + real DNS payload
            header = data[:8].decode("utf-8", errors="ignore")
            dns_query_bytes = data[8:]

            # Parse DNS query
            dns_record = DNSRecord.parse(dns_query_bytes)
            qname = str(dns_record.q.qname)
            qtype = QTYPE[dns_record.q.qtype]
            print("qtype: ", qtype)

            # Pick IP
            ip = resolve_ip(header)

            # Build DNS response
            reply = dns_record.reply()
            
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=60))


            # Send back (note: prepend same custom header before DNS response)
            response_data = header.encode() + reply.pack()
            sock.sendto(response_data, addr)

            print(f"[+] {header} {qname} -> {ip}")

    except KeyboardInterrupt:
        print("\nStopping DNS server.")

if __name__ == "__main__":
    start_dns_server()
