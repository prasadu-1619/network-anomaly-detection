# consumer_plot.py - Enhanced Network Traffic Anomaly Detection System v2.2
import pandas as pd
import numpy as np
from kafka import KafkaConsumer
import json
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from dash import Dash, dcc, html, callback, ctx
from dash.dependencies import Output, Input, State
import plotly.graph_objs as go
from plotly.subplots import make_subplots
import threading
from datetime import datetime
from collections import deque
import os
import sys

# Configuration
KAFKA_TOPIC = 'network_traffic'
KAFKA_SERVER = 'localhost:9092'
BUFFER_SIZE = 100
MAX_DISPLAY_POINTS = 500
INITIAL_TRAINING_SIZE = 200
ANOMALY_SCORE_THRESHOLD = -0.1
DATA_STORAGE_FILE = 'network_traffic_data.json'
CLEAR_DATA_ON_STARTUP = True

# Initialize components
consumer = KafkaConsumer(
    KAFKA_TOPIC,
    bootstrap_servers=KAFKA_SERVER,
    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
    auto_offset_reset='latest',
    enable_auto_commit=True
)

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

# Persistent storage for all data
all_traffic_data = []
data_lock = threading.Lock()

# Dynamic configuration
config = {
    "buffer_size": BUFFER_SIZE,
    "lock": threading.Lock()
}

# Clear data on startup if configured
if CLEAR_DATA_ON_STARTUP and os.path.exists(DATA_STORAGE_FILE):
    os.remove(DATA_STORAGE_FILE)
    print(f"Cleared existing data file: {DATA_STORAGE_FILE}")

# Load existing data if available
if os.path.exists(DATA_STORAGE_FILE):
    try:
        with open(DATA_STORAGE_FILE, 'r') as f:
            all_traffic_data = json.load(f)
        print(f"Loaded {len(all_traffic_data)} existing records")
    except:
        all_traffic_data = []

# ML Model and Scaler
model = IsolationForest(
    contamination='auto',
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
    "last_updated": None
}

# Dash App
app = Dash(__name__)
app.title = "Network Intrusion Detection System"

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
    dcc.Interval(id='interval-component', interval=1000, n_intervals=0)
    
], style={
    'minHeight': '100vh',
    'fontFamily': "'Inter', 'Segoe UI', sans-serif",
    'paddingBottom': '50px',
    'backgroundColor': 'rgba(0, 0, 0, 0.1)'
})


# Kafka consumer thread
def consume_data():
    global data_buffer, plot_data, stats, model_trained, training_data, all_traffic_data
    
    print("Starting Kafka consumer...")
    print("Collecting initial training data...")
    
    for message in consumer:
        try:
            traffic = message.value
            traffic['timestamp'] = datetime.now().isoformat()
            data_buffer.append(traffic)
            
            # Initial training phase
            if not model_trained:
                training_data.extend(data_buffer)
                if len(training_data) >= INITIAL_TRAINING_SIZE:
                    print(f"Training model on {len(training_data)} samples...")
                    train_df = pd.DataFrame(training_data)
                    
                    train_df['bytes_ratio'] = train_df['bytes_sent'] / (train_df['bytes_received'] + 1)
                    train_df['bytes_per_packet'] = (train_df['bytes_sent'] + train_df['bytes_received']) / (train_df['packets'] + 1)
                    train_df['throughput'] = (train_df['bytes_sent'] + train_df['bytes_received']) / (train_df['duration'] + 0.1)
                    
                    train_features = train_df[['bytes_sent', 'bytes_received', 'packets', 'duration', 
                                               'bytes_ratio', 'bytes_per_packet', 'throughput']]
                    
                    scaler.fit(train_features)
                    features_scaled = scaler.transform(train_features)
                    model.fit(features_scaled)
                    
                    model_trained = True
                    print("Model trained! Now detecting anomalies...")
                    data_buffer.clear()
                continue
            
            # Use dynamic buffer size
            current_buffer_size = config["buffer_size"]
            
            if len(data_buffer) >= current_buffer_size:
                df = pd.DataFrame(data_buffer)
                
                df['bytes_ratio'] = df['bytes_sent'] / (df['bytes_received'] + 1)
                df['bytes_per_packet'] = (df['bytes_sent'] + df['bytes_received']) / (df['packets'] + 1)
                df['throughput'] = (df['bytes_sent'] + df['bytes_received']) / (df['duration'] + 0.1)
                
                extended_features = df[['bytes_sent', 'bytes_received', 'packets', 'duration', 
                                       'bytes_ratio', 'bytes_per_packet', 'throughput']]
                
                features_scaled = scaler.transform(extended_features)
                scores = model.score_samples(features_scaled)
                
                score_mean = np.mean(scores)
                score_std = np.std(scores)
                dynamic_threshold = score_mean - (2 * score_std)
                
                preds = np.where(scores < dynamic_threshold, -1, 1)
                
                df['anomaly'] = preds
                df['anomaly_score'] = scores
                
                # Store data with anomaly flag
                with data_lock:
                    for idx, row in df.iterrows():
                        record = {
                            'timestamp': row['timestamp'],
                            'bytes_sent': int(row['bytes_sent']),
                            'bytes_received': int(row['bytes_received']),
                            'packets': int(row['packets']),
                            'duration': float(row['duration']),
                            'protocol': row.get('protocol', 'Unknown'),
                            'src_port': int(row.get('src_port', 0)),
                            'dst_port': int(row.get('dst_port', 0)),
                            'is_anomaly': 'Yes' if row['anomaly'] == -1 else 'No',
                            'anomaly_score': float(row['anomaly_score'])
                        }
                        all_traffic_data.append(record)
                        
                        # Update plot data
                        plot_data["timestamp"].append(row['timestamp'])
                        plot_data["bytes_sent"].append(row['bytes_sent'])
                        plot_data["bytes_received"].append(row['bytes_received'])
                        plot_data["packets"].append(row['packets'])
                        plot_data["duration"].append(row['duration'])
                        plot_data["anomaly"].append(row['anomaly'])
                        plot_data["anomaly_score"].append(row['anomaly_score'])
                        plot_data["protocol"].append(row.get('protocol', 'Unknown'))
                        plot_data["src_port"].append(row.get('src_port', 0))
                        plot_data["dst_port"].append(row.get('dst_port', 0))
                
                anomaly_count_batch = len(df[df['anomaly'] == -1])
                stats["total_packets"] += len(df)
                stats["anomaly_count"] += anomaly_count_batch
                stats["normal_count"] += len(df[df['anomaly'] == 1])
                stats["last_updated"] = datetime.now()
                
                # Save to JSON file periodically
                if stats["total_packets"] % 500 == 0:
                    with data_lock:
                        with open(DATA_STORAGE_FILE, 'w') as f:
                            json.dump(all_traffic_data, f, indent=2)
                    print(f"Saved {len(all_traffic_data)} records to {DATA_STORAGE_FILE}")
                
                batch_anomaly_rate = (anomaly_count_batch / len(df)) * 100
                data_buffer.clear()
                
                print(f"Batch: {len(df)} samples | Anomalies: {anomaly_count_batch} ({batch_anomaly_rate:.1f}%)")
                
        except Exception as e:
            print(f"Error processing message: {e}")
            continue

threading.Thread(target=consume_data, daemon=True).start()


# Update Buffer Size Callback
@app.callback(
    [Output('buffer-display', 'children'),
     Output('buffer-status', 'children')],
    Input('buffer-update-btn', 'n_clicks'),
    State('buffer-size-input', 'value'),
    prevent_initial_call=True
)
def update_buffer_size(n_clicks, new_size):
    if new_size is None or new_size < 10 or new_size > 1000:
        return f"{config['buffer_size']} samples", "Invalid: Range 10-1000"
    
    with config["lock"]:
        config["buffer_size"] = new_size
    
    return f"{new_size} samples", f"Buffer size updated to {new_size}"


# Download CSV callback
@app.callback(
    Output("download-csv", "data"),
    Input("download-btn", "n_clicks"),
    prevent_initial_call=True
)
def generate_csv_report(n_clicks):
    with data_lock:
        if not all_traffic_data:
            return None
        
        df = pd.DataFrame(all_traffic_data)
        
        total_records = len(df)
        total_anomalies = len(df[df['is_anomaly'] == 'Yes'])
        anomaly_percentage = (total_anomalies / total_records * 100) if total_records > 0 else 0
        
        column_order = ['timestamp', 'protocol', 'src_port', 'dst_port', 'bytes_sent', 
                       'bytes_received', 'packets', 'duration', 'anomaly_score', 'is_anomaly']
        df = df[column_order]
        
        csv_string = df.to_csv(index=False)
        summary_line = f"\nSUMMARY,,,,,,,,,\n"
        summary_line += f"Total Records,{total_records},,,,,,,,\n"
        summary_line += f"Total Anomalies,{total_anomalies},,,,,,,,\n"
        summary_line += f"Anomaly Percentage,{anomaly_percentage:.2f}%,,,,,,,,\n"
        
        csv_string += summary_line
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        return dict(
            content=csv_string,
            filename=f"network_traffic_report_{timestamp}.csv"
        )


# Update Statistics
@app.callback(
    [Output('total-packets', 'children'),
     Output('normal-count', 'children'),
     Output('anomaly-count', 'children'),
     Output('anomaly-rate', 'children')],
    Input('interval-component', 'n_intervals')
)
def update_stats(n):
    total = stats["total_packets"]
    normal = stats["normal_count"]
    anomaly = stats["anomaly_count"]
    rate = (anomaly / total * 100) if total > 0 else 0
    
    return str(total), str(normal), str(anomaly), f"{rate:.2f}%"


# Update Scatter Plot
@app.callback(
    Output('traffic-scatter', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_scatter(n):
    if not plot_data["bytes_sent"]:
        return {
            'data': [],
            'layout': go.Layout(
                title="Initializing data stream...",
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': '#b8b8d4', 'size': 14}
            )
        }
    
    df = pd.DataFrame(plot_data)
    df['label'] = df['anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')
    
    normal_df = df[df['label'] == 'Normal']
    anomaly_df = df[df['label'] == 'Anomaly']
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=normal_df['bytes_sent'],
        y=normal_df['bytes_received'],
        mode='markers',
        name='Normal Traffic',
        marker=dict(
            color='#00ff88',
            size=8,
            opacity=0.7,
            line=dict(color='#00ff88', width=1)
        ),
        hovertemplate='<b>Normal</b><br>Sent: %{x}<br>Received: %{y}<extra></extra>'
    ))
    
    fig.add_trace(go.Scatter(
        x=anomaly_df['bytes_sent'],
        y=anomaly_df['bytes_received'],
        mode='markers',
        name='Anomaly',
        marker=dict(
            color='#ff0055',
            size=12,
            symbol='x',
            line=dict(color='#ff0055', width=2),
            opacity=0.95
        ),
        hovertemplate='<b>ANOMALY</b><br>Sent: %{x}<br>Received: %{y}<extra></extra>'
    ))
    
    fig.update_layout(
        title={
            'text': "Traffic Pattern Analysis",
            'font': {'size': 18, 'color': '#00d4ff', 'family': 'Inter'},
            'x': 0.5,
            'xanchor': 'center'
        },
        xaxis_title="Bytes Sent",
        yaxis_title="Bytes Received",
        hovermode='closest',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(20, 30, 60, 0.3)',
        font={'color': '#b8b8d4', 'size': 11},
        showlegend=True,
        legend=dict(
            x=0.02,
            y=0.98,
            bgcolor='rgba(30, 30, 50, 0.8)',
            bordercolor='rgba(0, 212, 255, 0.3)',
            borderwidth=1
        ),
        xaxis=dict(gridcolor='rgba(255, 255, 255, 0.1)'),
        yaxis=dict(gridcolor='rgba(255, 255, 255, 0.1)'),
        margin=dict(l=70, r=50, t=60, b=60)
    )
    
    return fig


# Update Protocol Pie Chart
@app.callback(
    Output('protocol-pie', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_protocol_pie(n):
    if not plot_data["protocol"]:
        return {
            'data': [],
            'layout': go.Layout(
                title="Collecting protocol data...",
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': '#b8b8d4', 'size': 12}
            )
        }
    
    df = pd.DataFrame(plot_data)
    protocol_counts = df['protocol'].value_counts()
    
    colors = ['#00d4ff', '#00ff88', '#ffa500', '#ff0055', '#ff6b9d', '#c44569', '#b19cd9', '#ffd700']
    
    fig = go.Figure(data=[go.Pie(
        labels=protocol_counts.index,
        values=protocol_counts.values,
        marker=dict(colors=colors, line=dict(color='rgba(30, 30, 50, 0.9)', width=2)),
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>',
        textinfo='label+percent',
        textfont=dict(color='#ffffff', size=11)
    )])
    
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font={'color': '#b8b8d4', 'size': 11},
        showlegend=True,
        legend=dict(
            bgcolor='rgba(30, 30, 50, 0.7)',
            bordercolor='rgba(0, 212, 255, 0.3)',
            borderwidth=1,
            font=dict(size=10)
        ),
        margin=dict(l=20, r=20, t=20, b=20)
    )
    
    return fig


# Update Anomaly Score Histogram
@app.callback(
    Output('anomaly-histogram', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_anomaly_histogram(n):
    if not plot_data["anomaly_score"]:
        return {
            'data': [],
            'layout': go.Layout(
                title="Collecting anomaly scores...",
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': '#b8b8d4', 'size': 12}
            )
        }
    
    df = pd.DataFrame(plot_data)
    normal_scores = df[df['anomaly'] == 1]['anomaly_score']
    anomaly_scores = df[df['anomaly'] == -1]['anomaly_score']
    
    fig = go.Figure()
    
    fig.add_trace(go.Histogram(
        x=normal_scores,
        name='Normal',
        marker_color='#00ff88',
        opacity=0.7,
        nbinsx=30
    ))
    
    fig.add_trace(go.Histogram(
        x=anomaly_scores,
        name='Anomaly',
        marker_color='#ff0055',
        opacity=0.8,
        nbinsx=30
    ))
    
    fig.update_layout(
        title={
            'text': "Anomaly Score Distribution",
            'font': {'size': 14, 'color': '#ffa500'},
            'x': 0.5,
            'xanchor': 'center'
        },
        xaxis_title="Anomaly Score",
        yaxis_title="Frequency",
        barmode='overlay',
        hovermode='x unified',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(20, 30, 60, 0.3)',
        font={'color': '#b8b8d4', 'size': 10},
        legend=dict(
            bgcolor='rgba(30, 30, 50, 0.7)',
            bordercolor='rgba(0, 212, 255, 0.3)',
            borderwidth=1,
            font=dict(size=10)
        ),
        xaxis=dict(gridcolor='rgba(255, 255, 255, 0.1)'),
        yaxis=dict(gridcolor='rgba(255, 255, 255, 0.1)'),
        margin=dict(l=60, r=20, t=50, b=50)
    )
    
    return fig


# Update Time Series
@app.callback(
    Output('time-series', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_timeseries(n):
    if not plot_data["bytes_sent"]:
        return {
            'data': [],
            'layout': go.Layout(
                title="Initializing data stream...",
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font={'color': '#b8b8d4', 'size': 14}
            )
        }
    
    df = pd.DataFrame(plot_data)
    df['index'] = range(len(df))
    
    fig = make_subplots(
        rows=2, cols=1,
        subplot_titles=('Real-time Traffic Volume', 'Anomaly Confidence Score'),
        vertical_spacing=0.12,
        row_heights=[0.55, 0.45]
    )
    
    normal_df = df[df['anomaly'] == 1]
    anomaly_df = df[df['anomaly'] == -1]
    
    fig.add_trace(
        go.Scatter(
            x=normal_df['index'],
            y=normal_df['bytes_sent'],
            mode='lines+markers',
            name='Normal',
            line=dict(color='#00d4ff', width=2),
            marker=dict(size=5, color='#00d4ff'),
            fill='tozeroy',
            fillcolor='rgba(0, 212, 255, 0.15)'
        ),
        row=1, col=1
    )
    
    fig.add_trace(
        go.Scatter(
            x=anomaly_df['index'],
            y=anomaly_df['bytes_sent'],
            mode='markers',
            name='Anomaly',
            marker=dict(
                color='#ff0055',
                size=11,
                symbol='x',
                line=dict(color='#ff0055', width=2)
            ),
            showlegend=True
        ),
        row=1, col=1
    )
    
    fig.add_trace(
        go.Scatter(
            x=df['index'],
            y=df['anomaly_score'],
            mode='lines',
            name='Confidence',
            line=dict(color='#ffa500', width=2.5),
            fill='tozeroy',
            fillcolor='rgba(255, 165, 0, 0.2)',
            showlegend=False
        ),
        row=2, col=1
    )
    
    fig.add_hline(
        y=df['anomaly_score'].mean(),
        line_dash="dash",
        line_color="#ff0055",
        annotation_text="Threshold",
        annotation_position="right",
        row=2, col=1
    )
    
    fig.update_xaxes(title_text="Sample Index", row=1, col=1, gridcolor='rgba(255, 255, 255, 0.1)')
    fig.update_xaxes(title_text="Sample Index", row=2, col=1, gridcolor='rgba(255, 255, 255, 0.1)')
    fig.update_yaxes(title_text="Bytes Sent", row=1, col=1, gridcolor='rgba(255, 255, 255, 0.1)')
    fig.update_yaxes(title_text="Score", row=2, col=1, gridcolor='rgba(255, 255, 255, 0.1)')
    
    fig.update_layout(
        height=550,
        showlegend=True,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(20, 30, 60, 0.3)',
        font={'color': '#b8b8d4', 'size': 11},
        hovermode='x unified',
        legend=dict(
            bgcolor='rgba(30, 30, 50, 0.8)',
            bordercolor='rgba(0, 212, 255, 0.3)',
            borderwidth=1,
            x=0.02,
            y=0.98
        ),
        margin=dict(l=70, r=50, t=80, b=60)
    )
    
    for annotation in fig['layout']['annotations']:
        annotation['font'] = dict(size=14, color='#00d4ff', family='Inter')
    
    return fig


if __name__ == "__main__":
    print("=" * 70)
    print("Network Traffic Anomaly Detection System v2.2")
    print("=" * 70)
    print(f"Dashboard URL: http://localhost:8050")
    print(f"Model: Isolation Forest (Dynamic Threshold)")
    print(f"Initial Buffer Size: {BUFFER_SIZE} samples")
    print(f"Initial Training: {INITIAL_TRAINING_SIZE} samples")
    print(f"Kafka Topic: {KAFKA_TOPIC}")
    print(f"Data Storage: {DATA_STORAGE_FILE}")
    print(f"Existing Records: {len(all_traffic_data)}")
    print(f"Clear Data on Startup: {CLEAR_DATA_ON_STARTUP}")
    print("=" * 70)
    print("Buffer size can be dynamically adjusted from the web interface (10-1000)")
    print("=" * 70)
    
    app.run(debug=False, host="0.0.0.0", port=8050)