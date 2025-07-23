from scapy.all import sniff, IP, TCP, DNSQR, Raw
import datetime

# ⚠️ Suspicious ports list (expandable)
blacklisted_ports = [6667, 12345, 31337]

# Packet counter
packet_count = 0

def dns_sniffer(packet):
    if packet.haslayer(DNSQR):
        print("\n🌐 DNS Query:")
        print("  Source IP:", packet[IP].src)
        print("  Destination IP:", packet[IP].dst)
        print("  Domain Queried:", packet[DNSQR].qname.decode())

def tcp_packet(packet):
    if packet.haslayer(TCP):
        print("\n📦 TCP Packet:")
        print(f"  From {packet[IP].src}:{packet[TCP].sport} → {packet[IP].dst}:{packet[TCP].dport}")

def suspicious_packet(packet):
    if packet.haslayer(TCP):
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        if dport in blacklisted_ports or sport in blacklisted_ports:
            print("\n⚠️ Suspicious traffic detected!")
            print(f"  Port: {sport} → {dport}")
            print(f"  From {packet[IP].src} to {packet[IP].dst}")

def http_sniffer(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
            print("\n🌐 HTTP Traffic Detected:")
            print(f"  From {packet[IP].src} to {packet[IP].dst}")
            try:
                print("  HTTP Data:\n", payload.decode(errors="ignore"))
            except:
                print("  (Unable to decode payload)")

def full_sniffer(packet):
    global packet_count
    packet_count += 1
    print(f"\n📥 Packet #{packet_count} — {datetime.datetime.now().strftime('%H:%M:%S')}")
    
    if packet.haslayer(IP):
        dns_sniffer(packet)
        tcp_packet(packet)
        suspicious_packet(packet)
        http_sniffer(packet)

try:
    print("🔍 Sniffer started... Press Ctrl+C to stop.\n")
    sniff(filter="ip", prn=full_sniffer, store=0)
except KeyboardInterrupt:
    print(f"\n\n🛑 Sniffer stopped. Total packets captured: {packet_count}")
except Exception as e:
    print(f"⚠️ Error occurred: {e}")
# netmon/main.py