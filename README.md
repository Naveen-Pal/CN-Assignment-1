# Assignment 1: Custom DNS Resolution System Documentation

## Overview

This project implements a custom DNS resolution system consisting of a client and server that process DNS queries with custom headers. The system follows these steps:

1. The client parses a PCAP file to extract DNS query packets
2. Custom headers are added to each DNS query
3. Modified queries are sent to a custom DNS server
4. The server resolves IP addresses based on rules applied to the custom headers
5. Results are logged and presented in a report

## Components

### filterdns.py

From original dns.pcap capture file extracts only DNS query packets (QR=0) and saves the filtered packets to dns_queries.pcap

### modify_query.py

Adds an 8-byte custom header in "HHMMSSID" format in filtered dns_queries.pcap each DNS query
and saves modified packets to dns_custom_header.pcap.

### client.py

Creates a UDP socket to communicate with the server
Sends DNS packets to the server collects responce and saves them to dns_results.csv

### server.py

Listens for UDP packets on port 5359. For each received packet, Extracts the custom header and DNS query and applies time-based rules to determine which IP to return and sends a DNS response with the resolved IP.

## DNS Resolution Rules

The server implements time-based rules for IP address resolution:

- **Morning** (4:00-11:59): Uses IPs from pool starting at index 0, mod 5
- **Afternoon** (12:00-19:59): Uses IPs from pool starting at index 5, mod 5
- **Night** (20:00-3:59): Uses IPs from pool starting at index 10, mod 5

The actual IP selection is based on:
1. The time period
2. The session ID

## Results Analysis

The dns_results.csv file contains:
- Custom header values
- Domain names queried
- Resolved IP addresses

## Installation

Before running the system, install the required dependencies using pip:

```bash
pip install -r requirements.txt
```


## Running the System

To run the complete system:

1. First filter the DNS queries:
   ```bash
   python src/filterdns.py
   ```

2. Add custom headers to the filtered queries:
   ```bash
   python src/modify_query.py
   ```

3. Start the server in one terminal:
   ```bash
   python src/server.py
   ```

4. Run the client in another terminal:
   ```bash
   python src/client.py
   ```

5. View the results in dns_results.csv
