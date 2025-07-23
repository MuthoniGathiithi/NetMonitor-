from scapy.all import sniff, IP, DNSQR

def dns_sniffer(packet):
    if packet.haslayer(DNSQR):
        print("\n🔍 DNS Query Captured:")
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)
        print("Domain Queried:", packet[DNSQR].qname.decode())

print("📡 Listening for DNS queries on port 53...")
sniff(filter="port 53", prn=dns_sniffer, count=10)
# This code captures DNS queries on port 53 and prints the source and destination IP addresses along with the queried domain.
# It uses Scapy to sniff network packets and specifically looks for DNS query requests.