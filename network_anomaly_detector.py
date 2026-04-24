# network_anomaly_detector.py - Backend: Packet Sniffing + ML Anomaly Detection + REST API
# Frontend has been moved to streamlit_app.py
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from flask import Flask, jsonify, request, Response
import threading
from datetime import datetime
from collections import deque
import json
import random
import os
import sys
import logging
import time

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────
BUFFER_SIZE = 100
MAX_DISPLAY_POINTS = 200
INITIAL_TRAINING_SIZE = 80
ANOMALY_SCORE_THRESHOLD = -0.1
DATA_STORAGE_FILE = 'network_traffic_data.json'
CLEAR_DATA_ON_STARTUP = True
BACKEND_LOG_MAX = 2000
SAVE_TO_DISK_EVERY_N = 50
NORMAL_LOG_EVERY_N = 100
ANOMALY_LOG_EVERY_N = 10

# ─────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────
backend_logs = deque(maxlen=BACKEND_LOG_MAX)
backend_log_lock = threading.Lock()


class InMemoryLogHandler(logging.Handler):
    """Logging handler that stores recent backend logs in memory for /api/logs."""
    def emit(self, record):
        try:
            message = self.format(record)
            with backend_log_lock:
                backend_logs.append(message)
        except Exception:
            pass


backend_logger = logging.getLogger("cybershield.backend")
backend_logger.setLevel(logging.INFO)
if not backend_logger.handlers:
    log_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(log_formatter)
    backend_logger.addHandler(stream_handler)

    memory_handler = InMemoryLogHandler()
    memory_handler.setFormatter(log_formatter)
    backend_logger.addHandler(memory_handler)


def log_backend(message, level="info"):
    logger_fn = getattr(backend_logger, level, backend_logger.info)
    logger_fn(message)

# ─────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────
data_buffer = []

PLOT_FIELDS = [
    "timestamp", "bytes_sent", "bytes_received", "packets",
    "duration", "anomaly", "anomaly_score", "protocol",
    "src_port", "dst_port"
]

plot_data = {field: deque(maxlen=MAX_DISPLAY_POINTS) for field in PLOT_FIELDS}

# Persistent storage for all data
all_traffic_data = []
data_lock = threading.Lock()

# Dynamic configuration
config = {
    "buffer_size": BUFFER_SIZE,
    "lock": threading.Lock()
}


def resize_plot_buffers(new_size):
    """Resize dashboard deques while preserving the most recent points."""
    global plot_data
    for key in PLOT_FIELDS:
        existing = list(plot_data[key])
        plot_data[key] = deque(existing[-new_size:], maxlen=new_size)


# Packet counter and statistics
packet_count = 0
anomaly_injection_count = 0
anomaly_event_count = 0
start_time = datetime.now()

# Clear data on startup if configured
if CLEAR_DATA_ON_STARTUP and os.path.exists(DATA_STORAGE_FILE):
    os.remove(DATA_STORAGE_FILE)
    log_backend(f"Cleared existing data file: {DATA_STORAGE_FILE}")

# Load existing data if available
if os.path.exists(DATA_STORAGE_FILE):
    try:
        with open(DATA_STORAGE_FILE, 'r') as f:
            all_traffic_data = json.load(f)
        log_backend(f"Loaded {len(all_traffic_data)} existing records")
    except Exception:
        all_traffic_data = []

# ─────────────────────────────────────────────────────────────
# ML Model and Scaler
# ─────────────────────────────────────────────────────────────
model = IsolationForest(
    contamination=0.08,
    random_state=42,
    n_estimators=150,
    max_samples='auto',
    bootstrap=True
)
scaler = StandardScaler()
model_trained = False
training_data = []

# Statistics
stats = {
    "total_packets": len(all_traffic_data),
    "anomaly_count": sum(1 for item in all_traffic_data if item.get('is_anomaly') == 'Yes'),
    "normal_count": sum(1 for item in all_traffic_data if item.get('is_anomaly') == 'No'),
    "last_updated": None,
    "last_packet_time": None
}

# ─────────────────────────────────────────────────────────────
# Packet sniffer + ML processing
# ─────────────────────────────────────────────────────────────

def inject_anomaly():
    if random.random() < 0.08:
        global anomaly_injection_count
        anomaly_injection_count += 1
        return True
    return False


def packet_callback(packet):
    global packet_count, anomaly_injection_count, anomaly_event_count

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
                "timestamp": datetime.now().isoformat(),
                "simulated_anomaly": is_anomaly
            }

            if is_anomaly:
                anomaly_event_count += 1
                anomaly_type = random.choice(["high_packet_rate", "unusual_ports", "large_transfer"])

                if anomaly_type == "high_packet_rate":
                    record["packets"] = random.randint(500, 2000)
                    record["bytes_sent"] = random.randint(100, 500)
                elif anomaly_type == "unusual_ports":
                    record["dst_port"] = random.randint(1, 1000)
                elif anomaly_type == "large_transfer":
                    record["bytes_sent"] = random.randint(100000, 500000)
                    record["bytes_received"] = random.randint(50000, 200000)
                record["anomaly_type"] = anomaly_type

                if anomaly_event_count % ANOMALY_LOG_EVERY_N == 0:
                    log_backend(f"[ANOMALY] {anomaly_type} | {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
            else:
                if packet_count % NORMAL_LOG_EVERY_N == 0:
                    log_backend(f"[NORMAL] {protocol} | {ip_src}:{src_port} -> {ip_dst}:{dst_port}")

            # Add to buffer for processing
            add_traffic_data(record)
            packet_count += 1

            if packet_count % 50 == 0:
                elapsed = (datetime.now() - start_time).total_seconds()
                log_backend(f"Stats: {packet_count} packets | Normal: {packet_count - anomaly_injection_count} | Anomalies: {anomaly_injection_count} | Time: {elapsed/60:.1f}min")

    except Exception as e:
        log_backend(f"Error processing packet: {e}", level="error")


def add_traffic_data(traffic):
    """Add traffic data to buffer and process with ML model"""
    global data_buffer, plot_data, stats, model_trained, training_data, all_traffic_data

    with data_lock:
        data_buffer.append(traffic)

        # Initial training phase
        if not model_trained and len(training_data) < INITIAL_TRAINING_SIZE:
            # Keep training set as clean/normal as possible.
            if not traffic.get('simulated_anomaly', False):
                training_data.append(traffic)
            if len(training_data) % 10 == 0:
                log_backend(f"Collecting training data: {len(training_data)}/{INITIAL_TRAINING_SIZE}")

        # Train model once we have enough data
        elif not model_trained and len(training_data) >= INITIAL_TRAINING_SIZE:
            log_backend("Training Isolation Forest model...")
            X_train = np.array([[t['bytes_sent'], t['bytes_received'], t['packets'], t['duration']]
                               for t in training_data])
            scaler.fit(X_train)
            X_train_scaled = scaler.transform(X_train)
            model.fit(X_train_scaled)
            model_trained = True
            log_backend("Model trained successfully!")

        # Predict anomaly
        is_anomaly = False
        anomaly_score = 0

        if model_trained and len(data_buffer) >= 1:
            try:
                X = np.array([[traffic['bytes_sent'], traffic['bytes_received'],
                             traffic['packets'], traffic['duration']]])
                X_scaled = scaler.transform(X)
                anomaly_score = model.decision_function(X_scaled)[0]
                prediction = model.predict(X_scaled)[0]
                is_anomaly = (prediction == -1) or (anomaly_score < ANOMALY_SCORE_THRESHOLD)
            except Exception:
                is_anomaly = False
                anomaly_score = 0

        # Always surface synthetic stress events as anomalies in the dashboard.
        if traffic.get('simulated_anomaly', False):
            is_anomaly = True

        # Update plot data
        plot_data["timestamp"].append(datetime.now().isoformat())
        plot_data["bytes_sent"].append(traffic['bytes_sent'])
        plot_data["bytes_received"].append(traffic['bytes_received'])
        plot_data["packets"].append(traffic['packets'])
        plot_data["duration"].append(traffic['duration'])
        plot_data["anomaly"].append("Yes" if is_anomaly else "No")
        plot_data["anomaly_score"].append(anomaly_score)
        plot_data["protocol"].append(traffic['protocol'])
        plot_data["src_port"].append(traffic['src_port'])
        plot_data["dst_port"].append(traffic['dst_port'])

        # Update persistent storage
        record = dict(traffic)
        record['is_anomaly'] = 'Yes' if is_anomaly else 'No'
        record['anomaly_score'] = anomaly_score
        all_traffic_data.append(record)

        # Save to file periodically
        if len(all_traffic_data) % SAVE_TO_DISK_EVERY_N == 0:
            try:
                with open(DATA_STORAGE_FILE, 'w') as f:
                    json.dump(all_traffic_data, f, default=str)
            except Exception:
                pass

        # Update statistics
        stats["total_packets"] += 1
        if is_anomaly:
            stats["anomaly_count"] += 1
        else:
            stats["normal_count"] += 1
        stats["last_updated"] = datetime.now().isoformat()
        stats["last_packet_time"] = datetime.now().isoformat()


def simulate_traffic():
    """Generate synthetic traffic when real capture is unavailable."""
    log_backend("Starting simulated traffic generator (no pcap driver found)...")
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']
    while True:
        try:
            is_anomaly_flag = random.random() < 0.08
            protocol = random.choice(protocols)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 53, 22, 21, 8080, 3306])

            record = {
                "bytes_sent": random.randint(50, 2000),
                "bytes_received": random.randint(50, 5000),
                "packets": 1,
                "duration": round(random.uniform(0.001, 2.0), 3),
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "src_ip": f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
                "dst_ip": f"10.0.{random.randint(0,5)}.{random.randint(1,254)}",
                "timestamp": datetime.now().isoformat(),
                "simulated_anomaly": is_anomaly_flag
            }

            if is_anomaly_flag:
                anomaly_type = random.choice(["high_packet_rate", "unusual_ports", "large_transfer"])
                if anomaly_type == "high_packet_rate":
                    record["packets"] = random.randint(500, 2000)
                    record["bytes_sent"] = random.randint(100, 500)
                elif anomaly_type == "unusual_ports":
                    record["dst_port"] = random.randint(1, 1000)
                elif anomaly_type == "large_transfer":
                    record["bytes_sent"] = random.randint(100000, 500000)
                    record["bytes_received"] = random.randint(50000, 200000)
                record["anomaly_type"] = anomaly_type

            add_traffic_data(record)

            global packet_count
            packet_count += 1

            time.sleep(random.uniform(0.1, 0.5))
        except Exception as e:
            log_backend(f"Simulation error: {e}", level="error")
            time.sleep(1)


def sniff_packets():
    """Run packet sniffer in background thread.
    Falls back through: L2 -> L3 -> simulated traffic."""
    log_backend("Starting packet sniffer...")

    # Try Layer 2 (default — requires Npcap/WinPcap)
    try:
        sniff(prn=packet_callback, store=False, count=1, timeout=3)
        log_backend("Layer 2 capture available — starting live capture.")
        sniff(prn=packet_callback, store=False)
        return
    except Exception as e:
        log_backend(f"Layer 2 capture failed: {e}", level="warning")

    # Try Layer 3 socket (no Npcap needed)
    try:
        log_backend("Trying Layer 3 socket capture...")
        sniff(prn=packet_callback, store=False, count=1, timeout=3, opened_socket=conf.L3socket())
        log_backend("Layer 3 capture available — starting live capture.")
        sniff(prn=packet_callback, store=False, opened_socket=conf.L3socket())
        return
    except Exception as e:
        log_backend(f"Layer 3 capture failed: {e}", level="warning")

    # Fallback: simulated traffic
    log_backend("No packet capture driver available. Falling back to simulated traffic.", level="warning")
    log_backend("Install Npcap from https://npcap.com/ for real packet capture.", level="warning")
    simulate_traffic()

# ─────────────────────────────────────────────────────────────
# Flask REST API
# ─────────────────────────────────────────────────────────────
flask_app = Flask(__name__)

# Suppress Flask request logging to keep console clean
flask_log = logging.getLogger('werkzeug')
flask_log.setLevel(logging.WARNING)


@flask_app.after_request
def add_cors_headers(response):
    """Allow Streamlit (different port) to access backend."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response


@flask_app.route('/api/stats', methods=['GET'])
def api_stats():
    """Return current statistics."""
    with data_lock:
        return jsonify({
            "total_packets": stats["total_packets"],
            "anomaly_count": stats["anomaly_count"],
            "normal_count": stats["normal_count"],
            "last_updated": stats.get("last_updated"),
            "last_packet_time": stats.get("last_packet_time"),
            "model_trained": model_trained,
            "training_progress": len(training_data),
            "training_target": INITIAL_TRAINING_SIZE,
        })


@flask_app.route('/api/plot_data', methods=['GET'])
def api_plot_data():
    """Return current plot data for charts."""
    with data_lock:
        return jsonify({
            "timestamp": list(plot_data["timestamp"]),
            "bytes_sent": list(plot_data["bytes_sent"]),
            "bytes_received": list(plot_data["bytes_received"]),
            "packets": list(plot_data["packets"]),
            "duration": list(plot_data["duration"]),
            "anomaly": list(plot_data["anomaly"]),
            "anomaly_score": [float(s) for s in plot_data["anomaly_score"]],
            "protocol": list(plot_data["protocol"]),
            "src_port": list(plot_data["src_port"]),
            "dst_port": list(plot_data["dst_port"]),
        })


@flask_app.route('/api/config', methods=['GET'])
def api_config():
    """Return current configuration."""
    return jsonify({
        "buffer_size": config["buffer_size"],
        "max_display_points": MAX_DISPLAY_POINTS,
        "anomaly_score_threshold": ANOMALY_SCORE_THRESHOLD,
        "initial_training_size": INITIAL_TRAINING_SIZE,
    })


@flask_app.route('/api/config/buffer_size', methods=['POST'])
def api_update_buffer_size():
    """Update the buffer size."""
    body = request.get_json(force=True)
    new_size = body.get("buffer_size")
    if new_size is None or int(new_size) < 10 or int(new_size) > 1000:
        return jsonify({"error": "buffer_size must be between 10 and 1000"}), 400

    new_size = int(new_size)
    with data_lock:
        with config['lock']:
            config['buffer_size'] = new_size
        resize_plot_buffers(new_size)
    log_backend(f"Buffer size updated to {new_size}")
    return jsonify({"status": "ok", "buffer_size": new_size})


@flask_app.route('/api/traffic_data', methods=['GET'])
def api_traffic_data():
    """Return all traffic data for CSV export."""
    with data_lock:
        return jsonify(all_traffic_data)


@flask_app.route('/api/logs', methods=['GET'])
def api_logs():
    """Return backend logs."""
    with backend_log_lock:
        entries = list(backend_logs)
    return jsonify({"count": len(entries), "logs": entries})


@flask_app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "uptime_seconds": (datetime.now() - start_time).total_seconds()})


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    log_backend("=" * 70)
    log_backend("CyberShield - ML-Based Network Intrusion Detection System")
    log_backend("=" * 70)
    log_backend("Starting integrated packet sniffer + anomaly detection + REST API...")
    log_backend("REST API available at: http://127.0.0.1:8050")
    log_backend("  GET  /api/stats          — live statistics")
    log_backend("  GET  /api/plot_data      — chart data")
    log_backend("  GET  /api/config         — current config")
    log_backend("  POST /api/config/buffer_size — update buffer")
    log_backend("  GET  /api/traffic_data   — full traffic log (CSV export)")
    log_backend("  GET  /api/logs           — backend logs")
    log_backend("  GET  /health             — health check")
    log_backend("")
    log_backend("Streamlit frontend: run 'streamlit run streamlit_app.py' in another terminal")
    log_backend("Requires administrator/root privileges to capture packets!")
    log_backend("=" * 70)

    # Start packet sniffer in background thread
    sniffer_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniffer_thread.start()

    # Run Flask API server
    flask_app.run(debug=False, host='127.0.0.1', port=8050)
