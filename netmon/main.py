from scapy.all import sniff, IP, DNSQR,TCP

def dns_sniffer(packet):
    if packet.haslayer(DNSQR):
        print("\n🔍 DNS Query Captured:")
        print("Source IP:", packet[IP].src)
        print("Destination IP:", packet[IP].dst)
        print("Domain Queried:", packet[DNSQR].qname.decode())

print("📡 Listening for DNS queries on port 53...")
sniff(filter="port 53", prn=dns_sniffer, count=10)


def tcp_packet(packet):
    if packet.haslayer(TCP):
        print("\n📦 TCP Packet:")
        print(f"From {packet[IP].src}:{packet[TCP].sport} → {packet[IP].dst}:{packet[TCP].dport}")

blacklisted_ports = [6667, 12345, 31337]  # Example suspicious ports


def suspicious_packet(packet):
    if packet.haslayer(TCP):
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        if dport in blacklisted_ports or sport in blacklisted_ports:
            print("\n⚠️ Suspicious traffic detected!")
            print(f"Suspicious Port: {sport} → {dport}")
            print(f"From {packet[IP].src} to {packet[IP].dst}")

            
def full_sniffer(packet):
    # DNS Query handler (your earlier one)
    if packet.haslayer(DNSQR):
        print(f"\n🌐 DNS Query: {packet[IP].src} asked for {packet[DNSQR].qname.decode()}")

    # TCP handler
    tcp_packet(packet)

    # Suspicious check
    suspicious_packet(packet)

# Start sniffing
sniff(filter="ip", prn=full_sniffer, store=0)

# This code captures DNS queries on port 53 and prints the source and destination IP addresses along with the queried domain.
# It uses Scapy to sniff network packets and specifically looks for DNS query requests.