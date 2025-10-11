# producer.py - Advanced Network Traffic Simulator v2.0
from kafka import KafkaProducer
import json
import random
import time
import numpy as np
from datetime import datetime

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

class AdvancedTrafficSimulator:
    def __init__(self):
        self.protocols = ['HTTP', 'HTTPS', 'FTP', 'SSH', 'DNS', 'SMTP', 'IMAP', 'TELNET']
        
        # Time-based patterns for realism
        self.hour = datetime.now().hour
        
    def generate_normal_traffic(self):
        """Generate realistic normal traffic with time-based patterns"""
        protocol = random.choice(self.protocols)
        hour = datetime.now().hour
        
        # Traffic varies by time of day (business hours = more traffic)
        time_multiplier = 1.5 if 9 <= hour <= 17 else 0.7
        
        if protocol == 'HTTP':
            bytes_sent = int(random.randint(200, 1500) * time_multiplier)
            bytes_received = int(random.randint(1000, 15000) * time_multiplier)
            packets = random.randint(5, 50)
            duration = round(random.uniform(0.2, 3.0), 3)
        elif protocol == 'HTTPS':
            bytes_sent = int(random.randint(500, 2000) * time_multiplier)
            bytes_received = int(random.randint(2000, 20000) * time_multiplier)
            packets = random.randint(10, 80)
            duration = round(random.uniform(0.5, 4.0), 3)
        elif protocol == 'DNS':
            bytes_sent = random.randint(50, 200)
            bytes_received = random.randint(50, 500)
            packets = random.randint(1, 5)
            duration = round(random.uniform(0.01, 0.5), 3)
        elif protocol == 'SSH':
            bytes_sent = random.randint(100, 800)
            bytes_received = random.randint(100, 800)
            packets = random.randint(5, 30)
            duration = round(random.uniform(0.5, 10.0), 3)
        elif protocol == 'FTP':
            bytes_sent = int(random.randint(1000, 50000) * time_multiplier)
            bytes_received = int(random.randint(1000, 100000) * time_multiplier)
            packets = random.randint(20, 200)
            duration = round(random.uniform(1.0, 15.0), 3)
        elif protocol == 'SMTP':
            bytes_sent = random.randint(500, 5000)
            bytes_received = random.randint(200, 2000)
            packets = random.randint(5, 40)
            duration = round(random.uniform(0.5, 5.0), 3)
        elif protocol == 'IMAP':
            bytes_sent = random.randint(300, 1000)
            bytes_received = random.randint(1000, 10000)
            packets = random.randint(10, 60)
            duration = round(random.uniform(0.5, 5.0), 3)
        else:  # TELNET
            bytes_sent = random.randint(50, 500)
            bytes_received = random.randint(50, 500)
            packets = random.randint(5, 25)
            duration = round(random.uniform(0.5, 8.0), 3)
        
        return {
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "packets": packets,
            "duration": duration,
            "protocol": protocol,
            "src_port": random.randint(1024, 65535),
            "dst_port": self.get_standard_port(protocol)
        }
    
    def get_standard_port(self, protocol):
        """Get standard port for protocol"""
        port_map = {
            'HTTP': 80,
            'HTTPS': 443,
            'FTP': 21,
            'SSH': 22,
            'DNS': 53,
            'SMTP': 25,
            'IMAP': 143,
            'TELNET': 23
        }
        return port_map.get(protocol, 8080)
    
    def generate_ddos_attack(self):
        """Simulate DDoS attack - SYN flood pattern"""
        return {
            "bytes_sent": random.randint(40, 120),
            "bytes_received": random.randint(0, 80),
            "packets": random.randint(800, 3000),  # Extremely high packet count
            "duration": round(random.uniform(0.001, 0.3), 3),  # Very short
            "protocol": random.choice(['HTTP', 'HTTPS']),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 8080])
        }
    
    def generate_port_scan(self):
        """Simulate port scanning - sequential port probing"""
        return {
            "bytes_sent": random.randint(40, 100),
            "bytes_received": random.randint(0, 100),
            "packets": random.randint(1, 3),
            "duration": round(random.uniform(0.01, 0.15), 3),
            "protocol": "TCP",
            "src_port": random.randint(1024, 65535),
            "dst_port": random.randint(1, 65535)  # Random ports being scanned
        }
    
    def generate_data_exfiltration(self):
        """Simulate data exfiltration - large outbound, minimal inbound"""
        return {
            "bytes_sent": random.randint(150000, 800000),  # Massive upload
            "bytes_received": random.randint(100, 500),  # Minimal response
            "packets": random.randint(100, 400),
            "duration": round(random.uniform(15.0, 45.0), 3),  # Long duration
            "protocol": random.choice(['HTTPS', 'FTP', 'SSH']),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([443, 21, 22])
        }
    
    def generate_brute_force(self):
        """Simulate brute force attack - repeated login attempts"""
        return {
            "bytes_sent": random.randint(200, 600),
            "bytes_received": random.randint(150, 400),
            "packets": random.randint(8, 20),
            "duration": round(random.uniform(0.3, 1.5), 3),
            "protocol": random.choice(['SSH', 'FTP', 'TELNET']),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([22, 21, 23])
        }
    
    def generate_sql_injection(self):
        """Simulate SQL injection attempt - unusual HTTP patterns"""
        return {
            "bytes_sent": random.randint(800, 3000),  # Long query strings
            "bytes_received": random.randint(5000, 50000),  # Large DB response
            "packets": random.randint(15, 60),
            "duration": round(random.uniform(2.0, 8.0), 3),
            "protocol": random.choice(['HTTP', 'HTTPS']),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 8080])
        }
    
    def generate_dns_tunneling(self):
        """Simulate DNS tunneling - unusual DNS traffic"""
        return {
            "bytes_sent": random.randint(800, 2000),  # Unusually large DNS query
            "bytes_received": random.randint(800, 2000),
            "packets": random.randint(50, 150),  # Many DNS packets
            "duration": round(random.uniform(0.5, 3.0), 3),
            "protocol": "DNS",
            "src_port": random.randint(1024, 65535),
            "dst_port": 53
        }
    
    def generate_zero_day_exploit(self):
        """Simulate zero-day exploit - unusual protocol behavior"""
        protocol = random.choice(['HTTP', 'HTTPS', 'SSH'])
        return {
            "bytes_sent": random.randint(5000, 20000),  # Large payload
            "bytes_received": random.randint(100, 1000),
            "packets": random.randint(30, 100),
            "duration": round(random.uniform(1.0, 5.0), 3),
            "protocol": protocol,
            "src_port": random.randint(1024, 65535),
            "dst_port": self.get_standard_port(protocol)
        }
    
    def generate_traffic(self):
        """Generate traffic with realistic attack distribution"""
        rand = random.random()
        
        # 90% normal traffic, 10% various attacks
        if rand < 0.90:  # 90% normal
            return self.generate_normal_traffic(), "Normal"
        elif rand < 0.93:  # 3% DDoS
            return self.generate_ddos_attack(), "DDoS Attack"
        elif rand < 0.95:  # 2% Port Scan
            return self.generate_port_scan(), "Port Scan"
        elif rand < 0.97:  # 2% Data Exfiltration
            return self.generate_data_exfiltration(), "Data Exfiltration"
        elif rand < 0.98:  # 1% Brute Force
            return self.generate_brute_force(), "Brute Force"
        elif rand < 0.99:  # 1% SQL Injection
            return self.generate_sql_injection(), "SQL Injection"
        elif rand < 0.995:  # 0.5% DNS Tunneling
            return self.generate_dns_tunneling(), "DNS Tunneling"
        else:  # 0.5% Zero Day
            return self.generate_zero_day_exploit(), "Zero-Day Exploit"

# Initialize simulator
simulator = AdvancedTrafficSimulator()

print("=" * 70)
print("🚀 Advanced Network Traffic Simulator v2.0")
print("=" * 70)
print("📊 Traffic Distribution:")
print("  ✅ Normal Traffic: 90%")
print("  🔴 Attack Patterns: 10%")
print("     • DDoS Attacks: 3%")
print("     • Port Scans: 2%")
print("     • Data Exfiltration: 2%")
print("     • Brute Force: 1%")
print("     • SQL Injection: 1%")
print("     • DNS Tunneling: 0.5%")
print("     • Zero-Day Exploits: 0.5%")
print("=" * 70)
print("⏰ Time-based traffic patterns enabled")
print("🎯 Sending to Kafka topic: network_traffic")
print("=" * 70)
print()

count = 0
anomaly_count = 0
attack_types = {}

try:
    while True:
        traffic_data, traffic_type = simulator.generate_traffic()
        
        # Add timestamp
        traffic_data['timestamp'] = datetime.now().isoformat()
        
        # Send to Kafka
        producer.send('network_traffic', value=traffic_data)
        
        count += 1
        
        if traffic_type != "Normal":
            anomaly_count += 1
            attack_types[traffic_type] = attack_types.get(traffic_type, 0) + 1
            
            print(f"⚠️  [{count:05d}] {traffic_type:20s} | "
                  f"Proto: {traffic_data['protocol']:6s} | "
                  f"Bytes: {traffic_data['bytes_sent']:7d}↑/{traffic_data['bytes_received']:7d}↓ | "
                  f"Packets: {traffic_data['packets']:4d}")
        else:
            if count % 30 == 0:  # Print every 30th normal packet
                print(f"✅ [{count:05d}] {traffic_type:20s} | "
                      f"Proto: {traffic_data['protocol']:6s} | "
                      f"Bytes: {traffic_data['bytes_sent']:7d}↑/{traffic_data['bytes_received']:7d}↓")
        
        # Stats every 100 packets
        if count % 100 == 0:
            print("\n" + "=" * 70)
            print(f"📈 STATISTICS - Total Packets: {count}")
            print(f"   Normal: {count - anomaly_count} ({(count-anomaly_count)/count*100:.1f}%)")
            print(f"   Attacks: {anomaly_count} ({anomaly_count/count*100:.1f}%)")
            if attack_types:
                print(f"   Attack Breakdown:")
                for attack, num in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
                    print(f"      • {attack}: {num} ({num/count*100:.2f}%)")
            print("=" * 70 + "\n")
        
        # Variable delay for realistic traffic
        time.sleep(random.uniform(0.05, 0.4))
        
except KeyboardInterrupt:
    print("\n\n🛑 Shutting down producer...")
    print(f"📊 Final Stats: {count} packets sent, {anomaly_count} attacks detected")
    producer.close()