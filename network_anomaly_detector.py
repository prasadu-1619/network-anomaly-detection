# network_anomaly_detector.py - Integrated Network Anomaly Detection System (No Kafka)
# Real-time packet sniffing + ML anomaly detection + Dash dashboard
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from dash import Dash, dcc, html, callback, ctx
from dash.dependencies import Output, Input, State
import plotly.graph_objs as go
from plotly.subplots import make_subplots
import plotly.io as pio
import threading
from datetime import datetime
from collections import deque
import json
import random
import os
import sys
import logging
from html import escape as html_escape
from flask import jsonify, request

# Avoid runtime crashes from broken orjson serialization path in some Python setups.
pio.json.config.default_engine = "json"

# Configuration
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

backend_logs = deque(maxlen=BACKEND_LOG_MAX)
backend_log_lock = threading.Lock()


class InMemoryLogHandler(logging.Handler):
    """Logging handler that stores recent backend logs in memory for /logs route."""
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

# Data structures
data_buffer = []
plot_data = {
    "timestamp": deque(maxlen=MAX_DISPLAY_POINTS),
    "bytes_sent": deque(maxlen=MAX_DISPLAY_POINTS),
    "bytes_received": deque(maxlen=MAX_DISPLAY_POINTS),
    "packets": deque(maxlen=MAX_DISPLAY_POINTS),
    "duration": deque(maxlen=MAX_DISPLAY_POINTS),
    "anomaly": deque(maxlen=MAX_DISPLAY_POINTS),
    "anomaly_score": deque(maxlen=MAX_DISPLAY_POINTS),
    "protocol": deque(maxlen=MAX_DISPLAY_POINTS),
    "src_port": deque(maxlen=MAX_DISPLAY_POINTS),
    "dst_port": deque(maxlen=MAX_DISPLAY_POINTS)
}

PLOT_FIELDS = [
    "timestamp",
    "bytes_sent",
    "bytes_received",
    "packets",
    "duration",
    "anomaly",
    "anomaly_score",
    "protocol",
    "src_port",
    "dst_port"
]

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
    except:
        all_traffic_data = []

# ML Model and Scaler
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

# Dash App
app = Dash(__name__)
app.title = "Network Intrusion Detection System"


@app.server.route('/logs')
def show_backend_logs():
        """Show backend logs in browser. Use /logs?format=json for JSON output."""
        output_format = request.args.get("format", "html").lower()
        with backend_log_lock:
                entries = list(backend_logs)

        if output_format == "json":
                return jsonify({"count": len(entries), "logs": entries})

        rendered_logs = "\n".join(html_escape(line) for line in entries)
        html_doc = f"""
<!doctype html>
<html>
    <head>
        <title>CyberShield Backend Logs</title>
        <meta charset=\"utf-8\" />
        <style>
            body {{ background:#0b1020; color:#d4e4ff; font-family: Consolas, monospace; margin:0; }}
            .wrap {{ padding: 16px; }}
            h1 {{ margin: 0 0 8px 0; font-size: 20px; color: #8ad3ff; }}
            .meta {{ margin-bottom: 12px; color: #8aa2c2; }}
            pre {{ white-space: pre-wrap; word-break: break-word; background:#111933; border:1px solid #2a3f66; padding:12px; border-radius:8px; }}
            a {{ color: #7bd0ff; }}
        </style>
    </head>
    <body>
        <div class=\"wrap\">
            <h1>CyberShield Backend Logs</h1>
            <div class=\"meta\">Entries: {len(entries)} | JSON: <a href=\"/logs?format=json\">/logs?format=json</a></div>
            <pre>{rendered_logs if rendered_logs else 'No backend logs available yet.'}</pre>
        </div>
    </body>
</html>
"""
        return html_doc

# Enhanced Styling
CARD_STYLE = {
    'flex': '1',
    'padding': '20px',
    'background': 'linear-gradient(135deg, rgba(10, 10, 30, 0.9), rgba(30, 20, 60, 0.95))',
    'margin': '10px',
    'borderRadius': '15px',
    'boxShadow': '0 8px 32px 0 rgba(31, 38, 135, 0.37)',
    'backdropFilter': 'blur(10px)',
    'border': '1px solid rgba(255, 255, 255, 0.15)',
    'minWidth': '200px',
    'textAlign': 'center',
    'transition': 'all 0.3s ease'
}

app.layout = html.Div([
    dcc.Location(id='url', refresh=False),

    # Background
    html.Div(style={
        'position': 'fixed',
        'top': '0',
        'left': '0',
        'width': '100%',
        'height': '100%',
        'background': 'linear-gradient(135deg, #0a0a1e, #2d1b4e, #1a1a3e)',
        'zIndex': '-1'
    }),
    
    # Header
    html.Div([
        html.H1([
            "CyberShield ",
            html.Span("ML Based", style={'color': '#00d4ff'}),
            " Intrusion Detection"
        ], style={
            'textAlign': 'center',
            'color': '#ffffff',
            'marginBottom': '8px',
            'fontSize': '2.8em',
            'fontWeight': '700',
            'textShadow': '0 0 20px rgba(0, 212, 255, 0.6)',
            'letterSpacing': '1.5px'
        }),
        html.P("Real-time ML-based Anomaly Detection • Isolation Forest • Live Monitoring",
               style={
                   'textAlign': 'center',
                   'color': '#a8b8d4',
                   'fontSize': '15px',
                   'letterSpacing': '0.5px',
                   'marginBottom': '0',
                   'fontWeight': '300'
               })
        ,
        html.P(id='ui-heartbeat', children='UI heartbeat: initializing...', style={
            'textAlign': 'center',
            'color': '#7bd0ff',
            'fontSize': '12px',
            'letterSpacing': '0.3px',
            'marginTop': '8px'
        })
    ], style={
        'padding': '35px 20px 30px 20px',
        'background': 'linear-gradient(135deg, rgba(15, 12, 41, 0.95), rgba(60, 43, 120, 0.8))',
        'backdropFilter': 'blur(15px)',
        'borderBottom': '2px solid rgba(0, 212, 255, 0.4)',
        'marginBottom': '30px',
        'position': 'relative',
        'overflow': 'hidden'
    }),
    
    # Statistics Cards Row
    html.Div([
        html.Div([
            html.Div("📊", style={'fontSize': '40px', 'marginBottom': '12px'}),
            html.H4("Total Packets", style={
                'color': '#00d4ff',
                'marginBottom': '10px',
                'fontSize': '13px',
                'fontWeight': '600',
                'letterSpacing': '1px',
                'textTransform': 'uppercase'
            }),
            html.H2(id='total-packets', children=str(stats["total_packets"]), style={
                'color': '#ffffff',
                'fontSize': '38px',
                'fontWeight': '700',
                'margin': '0',
                'textShadow': '0 0 15px rgba(0, 212, 255, 0.5)'
            })
        ], style=CARD_STYLE),
        
        html.Div([
            html.Div("✅", style={'fontSize': '40px', 'marginBottom': '12px'}),
            html.H4("Normal Traffic", style={
                'color': '#00ff88',
                'marginBottom': '10px',
                'fontSize': '13px',
                'fontWeight': '600',
                'letterSpacing': '1px',
                'textTransform': 'uppercase'
            }),
            html.H2(id='normal-count', children=str(stats["normal_count"]), style={
                'color': '#ffffff',
                'fontSize': '38px',
                'fontWeight': '700',
                'margin': '0',
                'textShadow': '0 0 15px rgba(0, 255, 136, 0.5)'
            })
        ], style=CARD_STYLE),
        
        html.Div([
            html.Div("⚠️", style={'fontSize': '40px', 'marginBottom': '12px'}),
            html.H4("Anomalies", style={
                'color': '#ff0055',
                'marginBottom': '10px',
                'fontSize': '13px',
                'fontWeight': '600',
                'letterSpacing': '1px',
                'textTransform': 'uppercase'
            }),
            html.H2(id='anomaly-count', children=str(stats["anomaly_count"]), style={
                'color': '#ffffff',
                'fontSize': '38px',
                'fontWeight': '700',
                'margin': '0',
                'textShadow': '0 0 15px rgba(255, 0, 85, 0.5)'
            })
        ], style=CARD_STYLE),
        
        html.Div([
            html.Div("📈", style={'fontSize': '40px', 'marginBottom': '12px'}),
            html.H4("Threat Level", style={
                'color': '#ffa500',
                'marginBottom': '10px',
                'fontSize': '13px',
                'fontWeight': '600',
                'letterSpacing': '1px',
                'textTransform': 'uppercase'
            }),
            html.H2(id='anomaly-rate', children=f"{(stats['anomaly_count']/stats['total_packets']*100 if stats['total_packets'] > 0 else 0):.2f}%", style={
                'color': '#ffffff',
                'fontSize': '38px',
                'fontWeight': '700',
                'margin': '0',
                'textShadow': '0 0 15px rgba(255, 165, 0, 0.5)'
            })
        ], style=CARD_STYLE),
    ], style={
        'display': 'flex',
        'flexWrap': 'wrap',
        'padding': '0 10px',
        'justifyContent': 'center',
        'marginBottom': '30px'
    }),
    
    # Control Panel Row
    html.Div([
        html.Div([
            html.Button(
                [html.Span("📥 ", style={'marginRight': '8px'}), "Download CSV Report"],
                id='download-btn',
                n_clicks=0,
                style={
                    'padding': '16px 40px',
                    'fontSize': '16px',
                    'fontWeight': '600',
                    'background': 'linear-gradient(135deg, #00d4ff, #0099cc)',
                    'color': '#ffffff',
                    'border': 'none',
                    'borderRadius': '30px',
                    'cursor': 'pointer',
                    'boxShadow': '0 4px 20px rgba(0, 212, 255, 0.5)',
                    'transition': 'all 0.3s ease',
                    'letterSpacing': '0.5px',
                    'fontFamily': "'Inter', sans-serif"
                }
            ),
            dcc.Download(id="download-csv")
        ], style={'textAlign': 'center'}),
        
        html.Div([
            html.Label("Buffer Size:", style={
                'color': '#a8b8d4',
                'fontSize': '14px',
                'fontWeight': '600',
                'marginRight': '12px',
                'display': 'inline-block'
            }),
            dcc.Input(
                id='buffer-size-input',
                type='number',
                value=BUFFER_SIZE,
                min=10,
                max=1000,
                step=10,
                style={
                    'padding': '10px 15px',
                    'fontSize': '16px',
                    'borderRadius': '8px',
                    'border': '2px solid rgba(0, 212, 255, 0.4)',
                    'background': 'rgba(30, 30, 50, 0.8)',
                    'color': '#00d4ff',
                    'fontWeight': '600',
                    'width': '100px',
                    'textAlign': 'center'
                }
            ),
            html.Button(
                "Update",
                id='buffer-update-btn',
                n_clicks=0,
                style={
                    'padding': '10px 25px',
                    'fontSize': '14px',
                    'fontWeight': '600',
                    'background': 'linear-gradient(135deg, #00ff88, #00cc66)',
                    'color': '#ffffff',
                    'border': 'none',
                    'borderRadius': '8px',
                    'cursor': 'pointer',
                    'marginLeft': '10px',
                    'transition': 'all 0.3s ease',
                    'boxShadow': '0 2px 10px rgba(0, 255, 136, 0.3)'
                }
            ),
            html.Span(id='buffer-status', style={
                'color': '#00ff88',
                'marginLeft': '15px',
                'fontSize': '13px',
                'fontWeight': '600'
            })
        ], style={
            'textAlign': 'center',
            'display': 'inline-block',
            'marginLeft': '40px'
        })
    ], style={
        'textAlign': 'center',
        'marginBottom': '35px',
        'display': 'flex',
        'justifyContent': 'center',
        'flexWrap': 'wrap',
        'gap': '30px'
    }),
    
    # Main Graphs Container - Two Column Layout
    html.Div([
        # Scatter Plot
        html.Div([
            html.Div([
                html.H3("📍 Traffic Pattern Analysis", style={
                    'color': '#00d4ff',
                    'margin': '0 0 15px 0',
                    'fontSize': '18px',
                    'fontWeight': '600',
                    'textShadow': '0 0 10px rgba(0, 212, 255, 0.5)'
                }),
                dcc.Graph(id='traffic-scatter', style={'height': '500px', 'margin': '0'})
            ], style={
                'background': 'linear-gradient(135deg, rgba(10, 10, 30, 0.8), rgba(30, 20, 60, 0.85))',
                'borderRadius': '20px',
                'padding': '25px',
                'boxShadow': '0 10px 40px 0 rgba(31, 38, 135, 0.4)',
                'backdropFilter': 'blur(15px)',
                'border': '1px solid rgba(0, 212, 255, 0.2)',
                'height': '100%'
            })
        ], style={
            'flex': '1',
            'minWidth': '450px',
            'marginRight': '15px',
            'marginBottom': '30px'
        }),
        
        # Protocol Distribution & Port Analysis
        html.Div([
            html.Div([
                html.H3("📌 Network Protocols", style={
                    'color': '#00ff88',
                    'margin': '0 0 15px 0',
                    'fontSize': '18px',
                    'fontWeight': '600',
                    'textShadow': '0 0 10px rgba(0, 255, 136, 0.5)'
                }),
                dcc.Graph(id='protocol-pie', style={'height': '240px', 'margin': '0'})
            ], style={
                'background': 'linear-gradient(135deg, rgba(10, 10, 30, 0.8), rgba(30, 20, 60, 0.85))',
                'borderRadius': '20px',
                'padding': '25px',
                'boxShadow': '0 10px 40px 0 rgba(31, 38, 135, 0.4)',
                'backdropFilter': 'blur(15px)',
                'border': '1px solid rgba(0, 212, 255, 0.2)',
                'marginBottom': '20px'
            }),
            
            html.Div([
                html.H3("🎯 Anomaly Score Distribution", style={
                    'color': '#ffa500',
                    'margin': '0 0 15px 0',
                    'fontSize': '18px',
                    'fontWeight': '600',
                    'textShadow': '0 0 10px rgba(255, 165, 0, 0.5)'
                }),
                dcc.Graph(id='anomaly-histogram', style={'height': '240px', 'margin': '0'})
            ], style={
                'background': 'linear-gradient(135deg, rgba(10, 10, 30, 0.8), rgba(30, 20, 60, 0.85))',
                'borderRadius': '20px',
                'padding': '25px',
                'boxShadow': '0 10px 40px 0 rgba(31, 38, 135, 0.4)',
                'backdropFilter': 'blur(15px)',
                'border': '1px solid rgba(0, 212, 255, 0.2)'
            })
        ], style={
            'flex': '1',
            'minWidth': '400px'
        })
    ], style={
        'display': 'flex',
        'flexWrap': 'wrap',
        'padding': '0 15px',
        'marginBottom': '30px'
    }),
    
    # Time Series Plot - Full Width
    html.Div([
        html.H3("📈 Real-time Traffic & Anomaly Timeline", style={
            'color': '#00d4ff',
            'margin': '0 0 15px 0',
            'fontSize': '18px',
            'fontWeight': '600',
            'textShadow': '0 0 10px rgba(0, 212, 255, 0.5)'
        }),
        dcc.Graph(id='time-series', style={'height': '550px', 'margin': '0'})
    ], style={
        'background': 'linear-gradient(135deg, rgba(10, 10, 30, 0.8), rgba(30, 20, 60, 0.85))',
        'borderRadius': '20px',
        'padding': '25px',
        'margin': '0 15px 30px 15px',
        'boxShadow': '0 10px 40px 0 rgba(31, 38, 135, 0.4)',
        'backdropFilter': 'blur(15px)',
        'border': '1px solid rgba(0, 212, 255, 0.2)'
    }),

    # Teacher-Friendly Interpretation Panel
    html.Div([
        html.H3("🧠 Explainable Insights", style={
            'color': '#00d4ff',
            'margin': '0 0 12px 0',
            'fontSize': '18px',
            'fontWeight': '600',
            'textShadow': '0 0 10px rgba(0, 212, 255, 0.5)'
        }),
        html.Div(
            id='teacher-insights',
            children='Waiting for enough data to generate insights...',
            style={
                'color': '#d4e6ff',
                'fontSize': '14px',
                'lineHeight': '1.8',
                'whiteSpace': 'pre-line'
            }
        )
    ], style={
        'background': 'linear-gradient(135deg, rgba(10, 10, 30, 0.8), rgba(30, 20, 60, 0.85))',
        'borderRadius': '20px',
        'padding': '25px',
        'margin': '0 15px 30px 15px',
        'boxShadow': '0 10px 40px 0 rgba(31, 38, 135, 0.4)',
        'backdropFilter': 'blur(15px)',
        'border': '1px solid rgba(0, 212, 255, 0.2)'
    }),
    
    # Model Configuration
    html.Div([
        html.H4("⚙ System Configuration", style={
            'color': '#00d4ff',
            'marginBottom': '20px',
            'fontSize': '18px',
            'fontWeight': '600',
            'textAlign': 'center',
            'textShadow': '0 0 10px rgba(0, 212, 255, 0.5)',
            'margin': '0 0 20px 0'
        }),
        html.Div([
            html.Div([
                html.Span("Algorithm", style={'color': '#b8b8d4', 'fontSize': '12px', 'display': 'block', 'marginBottom': '8px'}),
                html.Span("Isolation Forest", style={'color': '#00d4ff', 'fontSize': '16px', 'fontWeight': '700'})
            ], style={'flex': '1', 'padding': '15px', 'textAlign': 'center'}),
            
            html.Div([
                html.Span("Detection Mode", style={'color': '#b8b8d4', 'fontSize': '12px', 'display': 'block', 'marginBottom': '8px'}),
                html.Span("Auto (Dynamic)", style={'color': '#ffa500', 'fontSize': '16px', 'fontWeight': '700'})
            ], style={'flex': '1', 'padding': '15px', 'textAlign': 'center'}),
            
            html.Div([
                html.Span("Active Buffer Size", style={'color': '#b8b8d4', 'fontSize': '12px', 'display': 'block', 'marginBottom': '8px'}),
                html.Span(id='buffer-display', children=f"{BUFFER_SIZE} samples", style={'color': '#00ff88', 'fontSize': '16px', 'fontWeight': '700'})
            ], style={'flex': '1', 'padding': '15px', 'textAlign': 'center'}),
            
            html.Div([
                html.Span("System Status", style={'color': '#b8b8d4', 'fontSize': '12px', 'display': 'block', 'marginBottom': '8px'}),
                html.Span("🟢 ACTIVE", style={'color': '#00ff88', 'fontSize': '16px', 'fontWeight': '700', 'textShadow': '0 0 10px rgba(0, 255, 136, 0.5)'})
            ], style={'flex': '1', 'padding': '15px', 'textAlign': 'center'})
        ], style={'display': 'flex', 'flexWrap': 'wrap', 'justifyContent': 'space-around'})
    ], style={
        'padding': '28px',
        'background': 'linear-gradient(135deg, rgba(10, 10, 30, 0.9), rgba(30, 20, 60, 0.95))',
        'margin': '0 15px 30px 15px',
        'borderRadius': '20px',
        'boxShadow': '0 10px 40px 0 rgba(31, 38, 135, 0.4)',
        'backdropFilter': 'blur(15px)',
        'border': '2px solid rgba(0, 212, 255, 0.3)'
    }),
    
    # Update Interval
    dcc.Interval(id='interval-component', interval=1000, n_intervals=0),

    # Hidden store used by lightweight clientside logger
    dcc.Store(id='frontend-action-log', data={"status": "initialized"})
    
], style={
    'minHeight': '100vh',
    'fontFamily': "'Inter', 'Segoe UI', sans-serif",
    'paddingBottom': '50px',
    'backgroundColor': 'rgba(0, 0, 0, 0.1)'
})


# Packet sniffer thread
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
            except:
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
            except:
                pass
        
        # Update statistics incrementally (faster than recounting entire history each packet).
        stats["total_packets"] += 1
        if is_anomaly:
            stats["anomaly_count"] += 1
        else:
            stats["normal_count"] += 1
        stats["last_updated"] = datetime.now()
        stats["last_packet_time"] = datetime.now()

def sniff_packets():
    """Run packet sniffer in background thread"""
    log_backend("Starting packet sniffer...")
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        log_backend("Packet sniffer stopped")
    except PermissionError:
        log_backend("Need administrator privileges to capture packets! Please run as Administrator.", level="error")
    except Exception as e:
        log_backend(f"Error in packet sniffer: {e}", level="error")

# Callbacks
@app.callback(
    Output('traffic-scatter', 'figure'),
    Output('protocol-pie', 'figure'),
    Output('anomaly-histogram', 'figure'),
    Output('time-series', 'figure'),
    Output('total-packets', 'children'),
    Output('normal-count', 'children'),
    Output('anomaly-count', 'children'),
    Output('anomaly-rate', 'children'),
    Output('buffer-display', 'children'),
    Output('teacher-insights', 'children'),
    Input('interval-component', 'n_intervals'),
    Input('buffer-size-input', 'value'),
    prevent_initial_call=False
)
def update_dashboard(n_intervals, buffer_size):
    """Update all dashboard components"""
    # Copy shared state quickly, then render figures outside lock to keep UI responsive.
    with data_lock:
        timestamps = list(plot_data['timestamp'])
        bytes_sent = list(plot_data['bytes_sent'])
        bytes_received = list(plot_data['bytes_received'])
        anomalies_series = list(plot_data['anomaly'])
        packets_series = list(plot_data['packets'])
        anomaly_scores = list(plot_data['anomaly_score'])
        protocols = list(plot_data['protocol'])
        active_buffer_size = config['buffer_size']

        total = stats["total_packets"]
        anomalies = stats["anomaly_count"]
        normal = stats["normal_count"]
        last_packet_time = stats.get("last_packet_time")

    if len(timestamps) == 0:
        empty_fig = go.Figure()
        empty_fig.add_annotation(text="Waiting for data...", showarrow=False)
        return empty_fig, empty_fig, empty_fig, empty_fig, "0", "0", "0", "0.00%", f"{active_buffer_size} samples", "Waiting for enough data to generate insights..."

    # Traffic Scatter Plot
    df_plot = pd.DataFrame({
        'bytes_sent': bytes_sent,
        'bytes_received': bytes_received,
        'anomaly': anomalies_series,
        'packets': packets_series,
        'anomaly_score': anomaly_scores
    })
        
    fig_scatter = go.Figure()

    normal_points = df_plot[df_plot['anomaly'] == 'No']
    anomaly_points = df_plot[df_plot['anomaly'] == 'Yes']

    fig_scatter.add_trace(go.Scatter(
        x=normal_points['bytes_sent'],
        y=normal_points['bytes_received'],
        mode='markers',
        name='Normal',
        marker=dict(size=6, color='#00ff88', opacity=0.6),
        text=normal_points['packets'],
        hovertemplate='<b>Normal Traffic</b><br>Sent: %{x}<br>Received: %{y}<br>Packets: %{text}<extra></extra>'
    ))

    fig_scatter.add_trace(go.Scatter(
        x=anomaly_points['bytes_sent'],
        y=anomaly_points['bytes_received'],
        mode='markers',
        name='Anomaly',
        marker=dict(size=8, color='#ff0055', symbol='diamond', opacity=0.9),
        text=anomaly_points['packets'],
        hovertemplate='<b>Anomalous Traffic</b><br>Sent: %{x}<br>Received: %{y}<br>Packets: %{text}<extra></extra>'
    ))

    fig_scatter.update_layout(
        title='Traffic Pattern Analysis (Outgoing vs Incoming Bytes)',
        xaxis_title='Bytes Sent (Outgoing Traffic)',
        yaxis_title='Bytes Received (Incoming Traffic)',
        hovermode='closest',
        plot_bgcolor='rgba(10,10,30,0.8)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff', family='Inter, sans-serif'),
        xaxis=dict(gridcolor='rgba(0,212,255,0.1)', showgrid=True),
        yaxis=dict(gridcolor='rgba(0,212,255,0.1)', showgrid=True),
        showlegend=True,
        legend=dict(x=0.02, y=0.98, bgcolor='rgba(10,10,30,0.7)', bordercolor='rgba(0,212,255,0.3)', borderwidth=1)
    )

    if len(normal_points) > 0:
        fig_scatter.add_vline(x=float(normal_points['bytes_sent'].median()), line_dash='dot', line_color='#00d4ff', opacity=0.5)
        fig_scatter.add_hline(y=float(normal_points['bytes_received'].median()), line_dash='dot', line_color='#00ff88', opacity=0.5)

    protocol_counts = pd.Series(protocols).value_counts()
    if len(protocol_counts) > 6:
        top_protocols = protocol_counts.head(5)
        other_sum = protocol_counts.iloc[5:].sum()
        protocol_counts = pd.concat([top_protocols, pd.Series({'Other': other_sum})])

    fig_pie = go.Figure(data=[go.Pie(
        labels=protocol_counts.index,
        values=protocol_counts.values,
        marker=dict(colors=['#00d4ff', '#00ff88', '#ffa500', '#ff0055', '#ff66ff', '#00ccff', '#ffcc00', '#66ff00']),
        textinfo='label+percent',
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    )])

    fig_pie.update_layout(
        plot_bgcolor='rgba(10,10,30,0.8)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff', family='Inter, sans-serif'),
        showlegend=True,
        legend=dict(x=0.7, y=1, bgcolor='rgba(10,10,30,0.7)', bordercolor='rgba(0,212,255,0.3)', borderwidth=1)
    )

    fig_hist = go.Figure()
    fig_hist.add_trace(go.Histogram(
        x=anomaly_scores,
        nbinsx=30,
        name='Anomaly Scores',
        marker=dict(color='#ffa500', line=dict(color='#ff8800', width=1)),
        hovertemplate='Score Range: %{x}<br>Count: %{y}<extra></extra>'
    ))

    fig_hist.add_vline(x=ANOMALY_SCORE_THRESHOLD, line_dash="dash", line_color="#ff0055",
                       annotation_text="Threshold", annotation_position="top left")
    if len(df_plot) > 0:
        score_mean = float(df_plot['anomaly_score'].mean())
        fig_hist.add_vline(x=score_mean, line_dash="dot", line_color="#00d4ff",
                           annotation_text="Mean", annotation_position="top right")

    fig_hist.update_layout(
        title='Anomaly Score Distribution',
        xaxis_title='Anomaly Score',
        yaxis_title='Frequency',
        plot_bgcolor='rgba(10,10,30,0.8)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff', family='Inter, sans-serif'),
        xaxis=dict(gridcolor='rgba(0,212,255,0.1)', showgrid=True),
        yaxis=dict(gridcolor='rgba(0,212,255,0.1)', showgrid=True),
        showlegend=False
    )

    fig_ts = make_subplots(specs=[[{"secondary_y": True}]])
    time_x = pd.to_datetime(timestamps, errors='coerce')

    fig_ts.add_trace(
        go.Scatter(x=time_x, y=bytes_sent,
                   name='Bytes Sent', line=dict(color='#00d4ff', width=2),
                   hovertemplate='Time: %{x}<br>Bytes Sent: %{y}<extra></extra>'),
        secondary_y=False
    )

    rolling_sent = pd.Series(bytes_sent).rolling(window=20, min_periods=1).mean()
    fig_ts.add_trace(
        go.Scatter(x=time_x, y=rolling_sent,
                   name='Bytes Sent (Rolling Avg)', line=dict(color='#7bd0ff', width=2, dash='dot'),
                   hovertemplate='Time: %{x}<br>Rolling Avg: %{y:.1f}<extra></extra>'),
        secondary_y=False
    )

    fig_ts.add_trace(
        go.Scatter(x=time_x, y=anomaly_scores,
                   name='Anomaly Score', line=dict(color='#ff0055', width=2, dash='dash'),
                   hovertemplate='Time: %{x}<br>Anomaly Score: %{y:.3f}<extra></extra>'),
        secondary_y=True
    )

    # Add anomaly markers instead of many vertical shapes for better performance.
    anomaly_idx = [i for i, flag in enumerate(anomalies_series) if flag == 'Yes' and i < len(time_x)]
    if anomaly_idx:
        anomaly_x = [time_x[i] for i in anomaly_idx]
        anomaly_y = [bytes_sent[i] for i in anomaly_idx]
        fig_ts.add_trace(
            go.Scatter(
                x=anomaly_x,
                y=anomaly_y,
                mode='markers',
                name='Anomaly Events',
                marker=dict(color='#ff0055', size=7, symbol='diamond'),
                hovertemplate='Time: %{x}<br>Bytes Sent: %{y}<br>Status: Anomaly<extra></extra>'
            ),
            secondary_y=False
        )

    fig_ts.update_xaxes(title_text="Wall-Clock Time", gridcolor='rgba(0,212,255,0.1)')
    fig_ts.update_yaxes(title_text="Bytes Sent", secondary_y=False, gridcolor='rgba(0,212,255,0.1)')
    fig_ts.update_yaxes(title_text="Anomaly Score", secondary_y=True, gridcolor='rgba(0,212,255,0.1)')

    fig_ts.update_layout(
        title='Real-time Traffic & Anomaly Timeline',
        plot_bgcolor='rgba(10,10,30,0.8)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ffffff', family='Inter, sans-serif'),
        hovermode='x unified',
        showlegend=True,
        legend=dict(x=0.02, y=0.98, bgcolor='rgba(10,10,30,0.7)', bordercolor='rgba(0,212,255,0.3)', borderwidth=1)
    )

    anomaly_rate = (anomalies / total * 100) if total > 0 else 0
    dominant_protocol = protocol_counts.index[0] if len(protocol_counts) > 0 else "N/A"
    avg_score = float(df_plot['anomaly_score'].mean()) if len(df_plot) > 0 else 0.0
    latest_score = float(df_plot['anomaly_score'].iloc[-1]) if len(df_plot) > 0 else 0.0
    packets_mean = float(df_plot['packets'].mean()) if len(df_plot) > 0 else 0.0

    teacher_summary = (
        f"1) Overall Threat Level: {anomaly_rate:.2f}% of observed traffic is anomalous.\n"
        f"2) Dominant Protocol: {dominant_protocol}.\n"
        f"3) Typical Packet Count: {packets_mean:.1f} packets per event (mean).\n"
        f"4) Anomaly Score Interpretation: current={latest_score:.3f}, average={avg_score:.3f}, threshold={ANOMALY_SCORE_THRESHOLD:.3f}.\n"
        f"5) Last Packet Seen: {last_packet_time.strftime('%H:%M:%S') if last_packet_time else 'N/A'}.\n"
        f"6) How to explain this dashboard: points far from cluster center, low anomaly scores, and red timeline markers indicate suspicious behavior."
    )

    return (
        fig_scatter,
        fig_pie,
        fig_hist,
        fig_ts,
        str(total),
        str(normal),
        str(anomalies),
        f"{anomaly_rate:.2f}%",
        f"{active_buffer_size} samples",
        teacher_summary,
    )


@app.callback(
    Output('ui-heartbeat', 'children'),
    Input('interval-component', 'n_intervals'),
    prevent_initial_call=False
)
def update_ui_heartbeat(n_intervals):
    with data_lock:
        last_packet_time = stats.get("last_packet_time")

    now = datetime.now()
    if last_packet_time:
        idle_seconds = (now - last_packet_time).total_seconds()
        return f"UI heartbeat: {now.strftime('%H:%M:%S')} | Last packet {idle_seconds:.0f}s ago"
    return f"UI heartbeat: {now.strftime('%H:%M:%S')} | Waiting for first packet"

@app.callback(
    Output('buffer-status', 'children'),
    Input('buffer-update-btn', 'n_clicks'),
    State('buffer-size-input', 'value'),
    prevent_initial_call=True
)
def update_buffer_size(n_clicks, new_size):
    if n_clicks:
        if not new_size or int(new_size) < 10:
            log_backend("Rejected buffer size update: value must be >= 10", level="warning")
            return "❌ Enter a value >= 10"

        new_size = int(new_size)
        with data_lock:
            with config['lock']:
                config['buffer_size'] = new_size
            resize_plot_buffers(new_size)
        log_backend(f"Buffer size updated to {new_size}")
        return f"✅ Updated to {new_size}"
    return ""

@app.callback(
    Output('download-csv', 'data'),
    Input('download-btn', 'n_clicks'),
    prevent_initial_call=True
)
def download_csv(n_clicks):
    if n_clicks:
        with data_lock:
            if all_traffic_data:
                df = pd.DataFrame(all_traffic_data)
                log_backend(f"CSV download requested with {len(all_traffic_data)} records")
                return dcc.send_data_frame(df.to_csv, "network_traffic_report.csv", index=False)
            # Return a valid empty CSV so download always works.
            empty_df = pd.DataFrame(columns=[
                "timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port",
                "bytes_sent", "bytes_received", "packets", "duration",
                "is_anomaly", "anomaly_score", "anomaly_type"
            ])
            log_backend("CSV download requested with no data; returning empty CSV", level="warning")
            return dcc.send_data_frame(empty_df.to_csv, "network_traffic_report.csv", index=False)
    return None

# Frontend action logger (runs in browser console).
# This captures all main dashboard interactions without changing UI behavior.
app.clientside_callback(
    """
    function(
        nIntervals,
        downloadClicks,
        bufferClicks,
        bufferValue,
        pathname
    ) {
        const now = new Date().toISOString();
        const eventMap = {
            interval_tick: nIntervals,
            download_clicks: downloadClicks,
            buffer_update_clicks: bufferClicks,
            buffer_value: bufferValue,
            pathname: pathname
        };

        const payload = {
            ts: now,
            event: "frontend_action",
            data: eventMap
        };

        try {
            if (!window.__cybershieldLogSeen) {
                window.__cybershieldLogSeen = {
                    interval_tick: -1,
                    download_clicks: -1,
                    buffer_update_clicks: -1,
                    buffer_value: null,
                    pathname: null
                };
            }

            const seen = window.__cybershieldLogSeen;
            const changed = [];

            if (typeof nIntervals === "number" && nIntervals !== seen.interval_tick) {
                changed.push("interval_tick");
                seen.interval_tick = nIntervals;
            }
            if (typeof downloadClicks === "number" && downloadClicks !== seen.download_clicks) {
                changed.push("download_click");
                seen.download_clicks = downloadClicks;
            }
            if (typeof bufferClicks === "number" && bufferClicks !== seen.buffer_update_clicks) {
                changed.push("buffer_update_click");
                seen.buffer_update_clicks = bufferClicks;
            }
            if (bufferValue !== seen.buffer_value) {
                changed.push("buffer_value_change");
                seen.buffer_value = bufferValue;
            }
            if (pathname !== seen.pathname) {
                changed.push("route_change");
                seen.pathname = pathname;
            }
            if (changed.length > 0) {
                console.groupCollapsed("[CyberShield Frontend] " + now + " | " + changed.join(", "));
                console.log("changed:", changed);
                console.log("payload:", payload);
                console.groupEnd();
            }
        } catch (err) {
            console.error("[CyberShield Frontend] logger_error", err);
        }

        return payload;
    }
    """,
    Output('frontend-action-log', 'data'),
    Input('interval-component', 'n_intervals'),
    Input('download-btn', 'n_clicks'),
    Input('buffer-update-btn', 'n_clicks'),
    Input('buffer-size-input', 'value'),
    Input('url', 'pathname')
)

if __name__ == '__main__':
    log_backend("=" * 70)
    log_backend("CyberShield - ML-Based Network Intrusion Detection System")
    log_backend("=" * 70)
    log_backend("Starting integrated packet sniffer + anomaly detection + dashboard...")
    log_backend("Dashboard will be available at: http://127.0.0.1:8050")
    log_backend("Requires administrator/root privileges to capture packets!")
    log_backend("Logs route available at: http://127.0.0.1:8050/logs")
    log_backend("=" * 70)
    
    # Start packet sniffer in background thread
    sniffer_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniffer_thread.start()
    
    # Run Dash app
    app.run_server(debug=False, host='127.0.0.1', port=8050)
