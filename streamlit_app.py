# streamlit_app.py - CyberShield Streamlit Frontend
# Connects to the Flask REST API backend (network_anomaly_detector.py)
import streamlit as st
import requests
import pandas as pd
import plotly.graph_objs as go
from plotly.subplots import make_subplots
from datetime import datetime
from streamlit_option_menu import option_menu

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────
API_BASE = "http://127.0.0.1:8050"
REFRESH_INTERVAL = 2

st.set_page_config(
    page_title="CyberShield — Network Intrusion Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────────────────────
# CSS — CyberShield dark theme + bento grid + tooltip icons
# ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    /* ── Reset & Global ─────────────────────── */
    .stApp {
        background: linear-gradient(135deg, #0a0a1e, #2d1b4e, #1a1a3e) !important;
        font-family: 'Inter', 'Segoe UI', sans-serif !important;
    }
    [data-testid="stSidebarCollapsedControl"],
    [data-testid="stSidebar"],
    #MainMenu, header[data-testid="stHeader"], footer,
    div[data-testid="stStatusWidget"] { display: none !important; }

    /* ── Header ──────────────────────────────── */
    .cyber-header {
        text-align: center;
        padding: 30px 20px 20px;
        background: linear-gradient(135deg, rgba(15,12,41,0.95), rgba(60,43,120,0.8));
        backdrop-filter: blur(15px);
        border-bottom: 2px solid rgba(0,212,255,0.4);
        border-radius: 0 0 16px 16px;
        margin: -1rem -1rem 20px -1rem;
    }
    .cyber-header h1 {
        color: #fff; font-size: 2.4em; font-weight: 700;
        text-shadow: 0 0 20px rgba(0,212,255,0.6);
        letter-spacing: 1px; margin: 0 0 8px 0;
    }
    .cyber-header .accent { color: #00d4ff; }
    .cyber-header .sub {
        color: #a8b8d4; font-size: 14px;
        letter-spacing: 0.5px; font-weight: 400; margin: 0;
    }
    .cyber-header .heartbeat { color: #7bd0ff; font-size: 12px; margin-top: 6px; font-family: monospace; }

    /* ── Stat cards ──────────────────────────── */
    .stat-card {
        background: linear-gradient(135deg, rgba(10,10,30,0.9), rgba(30,20,60,0.95));
        border: 1px solid rgba(255,255,255,0.12);
        border-radius: 12px; padding: 16px 14px;
        text-align: center;
        box-shadow: 0 4px 16px rgba(0,0,0,0.3);
        backdrop-filter: blur(10px);
        transition: all 0.2s ease;
        margin-bottom: 12px;
    }
    .stat-card:hover {
        border-color: rgba(0,212,255,0.4);
        box-shadow: 0 6px 20px rgba(0,212,255,0.15);
        transform: translateY(-2px);
    }
    .stat-card .icon { font-size: 30px; margin-bottom: 6px; }
    .stat-card .label {
        font-size: 11px; font-weight: 600; color: #b8b8d4;
        letter-spacing: 1px; text-transform: uppercase;
        margin-bottom: 4px;
    }
    .stat-card .value { font-size: 32px; font-weight: 700; color: #fff; margin: 0; }
    .c-total .value  { text-shadow: 0 0 10px rgba(0,212,255,0.5); }
    .c-normal .value { text-shadow: 0 0 10px rgba(0,255,136,0.5); }
    .c-anomaly .value{ text-shadow: 0 0 10px rgba(255,0,85,0.5); }
    .c-threat .value { text-shadow: 0 0 10px rgba(255,165,0,0.5); }

    /* ── Bento glass panel ───────────────────── */
    .bento {
        background: rgba(18,18,36,0.7) !important;
        border-radius: 12px; padding: 16px 20px 16px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255,255,255,0.08);
        margin-bottom: 16px;
    }

    /* ── Bento header with info tooltip ──────── */
    .bento-head {
        display: flex; align-items: center; justify-content: space-between;
        margin-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.05);
        padding-bottom: 8px;
    }
    .bento-head h3 {
        margin: 0; font-size: 14px; font-weight: 600;
        text-transform: uppercase; letter-spacing: 0.5px;
    }
    .info-tip {
        position: relative; display: inline-flex;
        align-items: center; justify-content: center;
        width: 20px; height: 20px;
        border-radius: 4px;
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.1);
        color: #a8b8d4; font-size: 11px; font-weight: 600;
        cursor: help; flex-shrink: 0;
    }
    .info-tip:hover { background: rgba(0,212,255,0.2); color: #00d4ff; border-color: #00d4ff; }
    .info-tip .tip-text {
        visibility: hidden; opacity: 0;
        position: absolute; bottom: calc(100% + 8px); right: -10px;
        width: 240px; padding: 10px 12px;
        background: rgba(20,20,35,0.98);
        border: 1px solid rgba(0,212,255,0.3);
        border-radius: 8px;
        color: #d4e6ff; font-size: 11.5px; font-weight: 400;
        line-height: 1.5; text-transform: none; letter-spacing: 0;
        box-shadow: 0 8px 30px rgba(0,0,0,0.6);
        z-index: 1000; transition: all 0.2s ease;
        text-align: left;
    }
    .info-tip .tip-text::after {
        content: ''; position: absolute;
        top: 100%; right: 14px;
        border: 5px solid transparent;
        border-top-color: rgba(0,212,255,0.3);
    }
    .info-tip:hover .tip-text { visibility: visible; opacity: 1; }

    /* ── Insights panel specialized typography ─ */
    .insight-line {
        color: #d4e6ff; font-size: 13.5px; line-height: 1.7;
        margin: 5px 0; display: block;
    }
    .insight-num { color: #00d4ff; font-weight: 700; margin-right: 4px; }
    .insight-val { color: #ffffff; font-weight: 600; }

    /* Streamlit block fixes */
    div[data-testid="stVerticalBlock"] > div { margin-bottom: -0.5rem; }
    
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def fetch(endpoint, method="GET", json_body=None, timeout=3):
    try:
        url = f"{API_BASE}{endpoint}"
        if method == "POST":
            r = requests.post(url, json=json_body, timeout=timeout)
        else:
            r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None

def dark_layout(**overrides):
    """Sleeker plotly layout without extra margins."""
    base = dict(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#a8b8d4', family='Inter, sans-serif', size=11),
        xaxis=dict(gridcolor='rgba(255,255,255,0.05)', showgrid=True, zeroline=False),
        yaxis=dict(gridcolor='rgba(255,255,255,0.05)', showgrid=True, zeroline=False),
        margin=dict(l=40, r=20, t=30, b=30),
    )
    base.update(overrides)
    return base

def bento_head(title, color, tooltip, icon=""):
    return f'''<div class="bento-head">
        <h3 style="color:{color};">{icon} {title}</h3>
        <span class="info-tip">i<span class="tip-text">{tooltip}</span></span>
    </div>'''


# ─────────────────────────────────────────────────────────────
# Header
# ─────────────────────────────────────────────────────────────
health = fetch("/health")
if health is None:
    st.markdown("""<div class="cyber-header">
        <h1>CyberShield <span class="accent">NIDS</span></h1>
        <p class="sub" style="color:#ff6b6b;">⚠️ Backend offline. Run: python network_anomaly_detector.py</p>
    </div>""", unsafe_allow_html=True)
    st.stop()

st.markdown(f"""<div class="cyber-header">
    <h1>CyberShield <span class="accent">NIDS</span></h1>
    <p class="sub">Network Intrusion Detection System — Active Monitoring</p>
    <p class="heartbeat">Uptime: {health['uptime_seconds']:.0f}s</p>
</div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# Navigation
# ─────────────────────────────────────────────────────────────
selected = option_menu(
    menu_title=None,
    options=["Live Dashboard", "Logs & Export", "Settings"],
    icons=["activity", "cloud-download", "sliders"],
    menu_icon="cast", default_index=0, orientation="horizontal",
    styles={
        "container": {"background": "rgba(18,18,36,0.8)", "border-radius": "12px", "border": "1px solid rgba(255,255,255,0.1)", "margin-bottom": "20px"},
        "icon": {"color": "#a8b8d4", "font-size": "16px"},
        "nav-link": {"font-size": "14px", "color": "#a8b8d4", "margin": "0px"},
        "nav-link-selected": {"background-color": "rgba(0,212,255,0.1)", "color": "#00d4ff", "font-weight": "600"}
    }
)

# ─────────────────────────────────────────────────────────────
# Tabs Logic
# ─────────────────────────────────────────────────────────────
if selected == "Live Dashboard":

    @st.fragment(run_every=REFRESH_INTERVAL)
    def live_dashboard():
        stats_data = fetch("/api/stats")
        plot_raw = fetch("/api/plot_data")
        config_data = fetch("/api/config")
        if not stats_data: return

        total = stats_data["total_packets"]
        anomalies = stats_data["anomaly_count"]
        threat_rate = (anomalies / total * 100) if total > 0 else 0.0

        # === ROW 1: METRICS ===
        c1, c2, c3, c4 = st.columns(4)
        with c1: st.markdown(f'<div class="stat-card c-total"><div class="icon">📊</div><div class="label">Total Packets</div><div class="value">{total:,}</div></div>', unsafe_allow_html=True)
        with c2: st.markdown(f'<div class="stat-card c-normal"><div class="icon">✅</div><div class="label">Normal</div><div class="value">{stats_data["normal_count"]:,}</div></div>', unsafe_allow_html=True)
        with c3: st.markdown(f'<div class="stat-card c-anomaly"><div class="icon">⚠️</div><div class="label">Anomalies</div><div class="value">{anomalies:,}</div></div>', unsafe_allow_html=True)
        with c4: st.markdown(f'<div class="stat-card c-threat"><div class="icon">📈</div><div class="label">Threat Level</div><div class="value">{threat_rate:.1f}%</div></div>', unsafe_allow_html=True)
        
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        if not plot_raw or len(plot_raw.get("timestamp", [])) == 0:
            st.info("⏳ Waiting for network data…")
            return

        df = pd.DataFrame(plot_raw)
        threshold = config_data.get("anomaly_score_threshold", -0.1) if config_data else -0.1

        # === ROW 2: DUAL ANALYSIS (SCATTER + PIE) ===
        # Using a perfectly symmetrical grid so tall/short components NEVER overlap
        r2_col1, r2_col2 = st.columns(2)

        with r2_col1:
            st.markdown(f'<div class="bento">{bento_head("Traffic Mapping", "#00d4ff", "Sent vs Received bytes. Outliers indicate anomalies.", "📍")}', unsafe_allow_html=True)
            fig_sc = go.Figure()
            n_df, a_df = df[df['anomaly'] == 'No'], df[df['anomaly'] == 'Yes']

            fig_sc.add_trace(go.Scatter(x=n_df['bytes_sent'], y=n_df['bytes_received'], mode='markers', name='Normal', marker=dict(size=6, color='#00ff88', opacity=0.6)))
            fig_sc.add_trace(go.Scatter(x=a_df['bytes_sent'], y=a_df['bytes_received'], mode='markers', name='Anomaly', marker=dict(size=10, color='#ff0055', symbol='x', line_width=1)))
            
            fig_sc.update_layout(**dark_layout(xaxis_title="Sent (Bytes)", yaxis_title="Received (Bytes)", height=320, legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01, bgcolor="rgba(0,0,0,0.5)")))
            st.plotly_chart(fig_sc, width="stretch", key="scatter")
            st.markdown('</div>', unsafe_allow_html=True)

        with r2_col2:
            st.markdown(f'<div class="bento">{bento_head("Protocol Mix", "#00ff88", "Network protocol distribution.", "📌")}', unsafe_allow_html=True)
            proto = df['protocol'].value_counts()
            fig_pie = go.Figure(data=[go.Pie(labels=proto.head(5).index, values=proto.head(5).values, hole=0.4, marker=dict(colors=['#00d4ff', '#00ff88', '#ffa500', '#ff0055']))])
            fig_pie.update_layout(**dark_layout(height=320))
            st.plotly_chart(fig_pie, width="stretch", key="pie")
            st.markdown('</div>', unsafe_allow_html=True)

        # === ROW 3: TIMELINE ===
        st.markdown(f'<div class="bento">{bento_head("Live Timeline", "#00d4ff", "Time-series of traffic volume & anomaly detections.", "📈")}', unsafe_allow_html=True)
        fig_ts = make_subplots(specs=[[{"secondary_y": True}]])
        time_x = pd.to_datetime(df['timestamp'], errors='coerce')
        
        fig_ts.add_trace(go.Scatter(x=time_x, y=df['bytes_sent'], name='Traffic Vol.', line=dict(color='#00d4ff', width=2)), secondary_y=False)
        fig_ts.add_trace(go.Scatter(x=time_x, y=df['anomaly_score'], name='Threat Score', line=dict(color='#ff0055', width=1, dash='dash')), secondary_y=True)

        amask = df['anomaly'] == 'Yes'
        if amask.any():
            fig_ts.add_trace(go.Scatter(x=time_x[amask], y=df.loc[amask, 'bytes_sent'], mode='markers', name='Anomalies', marker=dict(color='#ff0055', size=8, symbol='diamond')), secondary_y=False)

        fig_ts.update_layout(**dark_layout(height=350, hovermode="x unified", legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)))
        st.plotly_chart(fig_ts, width="stretch", key="timeline")
        st.markdown('</div>', unsafe_allow_html=True)

        # === ROW 4: DEEP DIVE (HISTOGRAM + INSIGHTS) ===
        r4_col1, r4_col2 = st.columns(2)

        with r4_col1:
            st.markdown(f'<div class="bento">{bento_head("Anomaly Scores", "#ffa500", "Distribution of Isolation Forest scores. Lower = higher threat.", "🎯")}', unsafe_allow_html=True)
            fig_hi = go.Figure()
            fig_hi.add_trace(go.Histogram(x=df['anomaly_score'], nbinsx=25, marker_color='#ffa500', opacity=0.8))
            fig_hi.add_vline(x=threshold, line_dash="dash", line_color="#ff0055")
            fig_hi.update_layout(**dark_layout(xaxis_title="Score", yaxis_title="Freq", height=280, showlegend=False))
            st.plotly_chart(fig_hi, width="stretch", key="hist")
            st.markdown('</div>', unsafe_allow_html=True)

        with r4_col2:
            st.markdown(f'<div class="bento" style="height:378px;">{bento_head("Explainable Insights", "#00d4ff", "Contextual breakdown of the current environment.", "🧠")}', unsafe_allow_html=True)
            dominant_proto = proto.index[0] if len(proto) > 0 else "N/A"
            avg_score = float(df['anomaly_score'].mean()) if len(df) > 0 else 0.0
            latest_score = float(df['anomaly_score'].iloc[-1]) if len(df) > 0 else 0.0
            pkt_mean = float(df['packets'].mean()) if len(df) > 0 else 0.0
            lp = stats_data.get("last_packet_time")
            lp_str = datetime.fromisoformat(lp).strftime('%H:%M:%S') if lp else "N/A"

            st.markdown(f"""
                <span class="insight-line"><span class="insight-num">1)</span> Threat Level: <span class="insight-val">{threat_rate:.2f}%</span> of traffic is anomalous.</span>
                <span class="insight-line"><span class="insight-num">2)</span> Dominant Protocol: <span class="insight-val">{dominant_proto}</span></span>
                <span class="insight-line"><span class="insight-num">3)</span> Avg Packet Count: <span class="insight-val">{pkt_mean:.1f}</span> per event.</span>
                <span class="insight-line"><span class="insight-num">4)</span> Anomaly Score: current: <span class="insight-val">{latest_score:.3f}</span> | avg: <span class="insight-val">{avg_score:.3f}</span></span>
                <span class="insight-line"><span class="insight-num">5)</span> Last Packet: <span class="insight-val">{lp_str}</span></span>
                <span class="insight-line" style="margin-top:20px; color:#a8b8d4;"><i>Outlier points and red markers deeply indicate suspicious traffic spikes requiring review.</i></span>
            """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
    live_dashboard()

elif selected == "Logs & Export":
    st.markdown(f'<div class="bento">{bento_head("Data Export", "#00ff88", "Export session traffic to CSV.", "📥")}', unsafe_allow_html=True)
    traffic_raw = fetch("/api/traffic_data")
    if traffic_raw:
        df_exp = pd.DataFrame(traffic_raw)
        st.dataframe(df_exp.tail(100), height=400, use_container_width=True)
        csv_data = df_exp.to_csv(index=False)
        st.download_button("📥 Save CSV", data=csv_data, file_name=f"export_{datetime.now().strftime('%H%M%S')}.csv", mime="text/csv")
    st.markdown('</div>', unsafe_allow_html=True)

elif selected == "Settings":
    config_data = fetch("/api/config")
    if config_data:
        st.markdown(f'<div class="bento">{bento_head("Engine Settings", "#00d4ff", "Adjust real-time buffer capacity limits.", "⚙")}', unsafe_allow_html=True)
        new_buf = st.number_input("Buffer Capacity", min_value=10, max_value=2000, value=config_data.get("buffer_size", 100))
        if st.button("Apply"):
            fetch("/api/config/buffer_size", method="POST", json_body={"buffer_size": int(new_buf)})
            st.success("Applied")
        st.markdown('</div>', unsafe_allow_html=True)
