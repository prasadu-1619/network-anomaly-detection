# packet_sniffer_windows.py
from scapy.all import sniff, IP, TCP, UDP, ICMP
from kafka import KafkaProducer
import json
from datetime import datetime
import random
import socket

producer = KafkaProducer(
    bootstrap_servers='192.168.34.134:9092',  # Point to WSL Kafka
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

packet_count = 0
anomaly_injection_count = 0
start_time = datetime.now()

def inject_anomaly():
    if random.random() < 0.08:
        global anomaly_injection_count
        anomaly_injection_count += 1
        return True
    return False

def packet_callback(packet):
    global packet_count
    
    try:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = "Unknown"
            src_port = 0
            dst_port = 0
            payload_size = len(packet.payload.payload) if packet.haslayer(IP) else 0
            
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"
            
            is_anomaly = inject_anomaly()
            
            record = {
                "bytes_sent": payload_size if is_anomaly else random.randint(50, 2000),
                "bytes_received": payload_size if is_anomaly else random.randint(50, 5000),
                "packets": 1,
                "duration": round(random.uniform(0.001, 2.0), 3),
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "src_ip": ip_src,
                "dst_ip": ip_dst,
                "timestamp": datetime.now().isoformat()
            }
            
            if is_anomaly:
                anomaly_type = random.choice(["high_packet_rate", "unusual_ports", "large_transfer"])
                
                if anomaly_type == "high_packet_rate":
                    record["packets"] = random.randint(500, 2000)
                    record["bytes_sent"] = random.randint(100, 500)
                elif anomaly_type == "unusual_ports":
                    record["dst_port"] = random.randint(1, 1000)
                elif anomaly_type == "large_transfer":
                    record["bytes_sent"] = random.randint(100000, 500000)
                    record["bytes_received"] = random.randint(50000, 200000)
                
                print(f"[ANOMALY] {anomaly_type} | {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
            else:
                if packet_count % 30 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    print(f"[NORMAL] {protocol} | {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
            
            producer.send('network_traffic', value=record)
            packet_count += 1
            
            if packet_count % 50 == 0:
                elapsed = (datetime.now() - start_time).total_seconds()
                rate = packet_count / elapsed if elapsed > 0 else 0
                print(f"\nStats: {packet_count} packets | Normal: {packet_count - anomaly_injection_count} | Anomalies: {anomaly_injection_count} | Time: {elapsed/60:.1f}min\n")
    
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Starting Windows Packet Sniffer")
    print("Sending to WSL Kafka at 192.168.34.134:9092")
    print("=" * 70)
    
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\nCaptured {packet_count} packets in {elapsed/60:.2f} minutes")
        producer.close()