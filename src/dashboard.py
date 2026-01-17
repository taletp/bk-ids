"""
Dashboard IDS/IPS sử dụng Streamlit
Giao diện Dark Mode theo tiêu chuẩn SOC
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from collections import deque, defaultdict
import time
import threading
import logging

logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="IDS/IPS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme
st.markdown("""
<style>
    [data-testid="stMetricValue"] {
        font-size: 28px;
    }
    
    .status-secure {
        color: #00FF00;
        font-weight: bold;
        font-size: 24px;
    }
    
    .status-attacking {
        color: #FF0000;
        font-weight: bold;
        font-size: 24px;
        animation: blink 1s infinite;
    }
    
    @keyframes blink {
        0%, 50% { opacity: 1; }
        51%, 100% { opacity: 0.3; }
    }
    
    .attack-alert {
        padding: 15px;
        border-radius: 5px;
        background-color: rgba(255, 0, 0, 0.1);
        border-left: 4px solid #FF0000;
        margin: 10px 0;
    }
    
    .normal-traffic {
        color: #00FF00;
    }
    
    .attack-traffic {
        color: #FF0000;
    }
</style>
""", unsafe_allow_html=True)


class DashboardState:
    """Quản lý state của dashboard"""
    
    def __init__(self, max_history: int = 1000):
        self.packets_buffer = deque(maxlen=1000)  # Giữ lại 1000 gói tin gần nhất
        self.alerts = deque(maxlen=max_history)
        self.stats = {
            'total_packets': 0,
            'total_attacks': 0,
            'normal_packets': 0,
            'attack_by_type': defaultdict(int),
            'blocked_ips': set(),
        }
        self.start_time = datetime.now()
    
    def add_packet(self, packet_info: dict):
        """Thêm gói tin vào buffer"""
        self.packets_buffer.append({
            'timestamp': datetime.now(),
            **packet_info
        })
        self.stats['total_packets'] += 1
    
    def add_alert(self, detection_result: dict):
        """Thêm alert"""
        if detection_result.get('is_attack'):
            self.alerts.append({
                'timestamp': datetime.now(),
                **detection_result
            })
            self.stats['total_attacks'] += 1
            attack_type = detection_result.get('attack_type', 'Unknown')
            self.stats['attack_by_type'][attack_type] += 1
            
            # Track blocked IPs
            if detection_result.get('src_ip'):
                self.stats['blocked_ips'].add(detection_result['src_ip'])
        else:
            self.stats['normal_packets'] += 1
    
    def get_uptime(self) -> str:
        """Lấy thời gian hoạt động"""
        uptime = datetime.now() - self.start_time
        hours = uptime.seconds // 3600
        minutes = (uptime.seconds % 3600) // 60
        return f"{uptime.days}d {hours}h {minutes}m"
    
    def get_attack_distribution(self) -> dict:
        """Lấy phân bố tấn công"""
        return dict(self.stats['attack_by_type'])


def initialize_session():
    """Khởi tạo Streamlit session state"""
    if 'dashboard_state' not in st.session_state:
        st.session_state.dashboard_state = DashboardState()
    if 'auto_block_enabled' not in st.session_state:
        st.session_state.auto_block_enabled = False
    if 'confidence_threshold' not in st.session_state:
        st.session_state.confidence_threshold = 0.85


def render_header():
    """Render header với system status"""
    col1, col2, col3, col4 = st.columns([2, 2, 2, 2])
    
    state = st.session_state.dashboard_state
    is_under_attack = state.stats['total_attacks'] > 0 and \
                      (datetime.now() - datetime.now()).total_seconds() < 60
    
    with col1:
        if is_under_attack:
            st.markdown(
                '<div class="status-attacking">🔴 UNDER ATTACK</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                '<div class="status-secure">🟢 SYSTEM SECURE</div>',
                unsafe_allow_html=True
            )
    
    with col2:
        st.metric("Total Packets", f"{state.stats['total_packets']:,}")
    
    with col3:
        st.metric("Total Attacks", f"{state.stats['total_attacks']:,}", 
                 delta=None, delta_color="off")
    
    with col4:
        st.metric("Uptime", state.get_uptime())


def render_live_traffic_graph():
    """Render biểu đồ traffic real-time"""
    state = st.session_state.dashboard_state
    
    # Chuẩn bị dữ liệu
    if len(state.packets_buffer) == 0:
        st.info("No packet data yet. Waiting for traffic...")
        return
    
    # Group packets by time (5-second buckets)
    time_buckets = defaultdict(lambda: {'normal': 0, 'attack': 0})
    
    for packet in state.packets_buffer:
        ts = packet['timestamp']
        # Round to nearest 5 seconds
        bucket_time = ts.replace(second=(ts.second // 5) * 5, microsecond=0)
        
        if packet.get('is_attack'):
            time_buckets[bucket_time]['attack'] += 1
        else:
            time_buckets[bucket_time]['normal'] += 1
    
    # Sort by time
    sorted_times = sorted(time_buckets.keys())
    
    # Create figure
    fig = go.Figure()
    
    # Add normal traffic line
    normal_counts = [time_buckets[t]['normal'] for t in sorted_times]
    fig.add_trace(go.Scatter(
        x=sorted_times,
        y=normal_counts,
        mode='lines',
        name='Normal Traffic',
        line=dict(color='#00FF00', width=2),
        fill='tozeroy'
    ))
    
    # Add attack traffic line
    attack_counts = [time_buckets[t]['attack'] for t in sorted_times]
    fig.add_trace(go.Scatter(
        x=sorted_times,
        y=attack_counts,
        mode='lines',
        name='Attack Traffic',
        line=dict(color='#FF0000', width=2),
        fill='tozeroy'
    ))
    
    # Update layout
    fig.update_layout(
        title="Live Traffic (5-second buckets)",
        xaxis_title="Time",
        yaxis_title="Packets/Bucket",
        hovermode='x unified',
        template='plotly_dark',
        height=400,
        margin=dict(l=0, r=0, t=30, b=0)
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_attack_distribution():
    """Render biểu đồ phân bố tấn công"""
    state = st.session_state.dashboard_state
    attack_dist = state.get_attack_distribution()
    
    if not attack_dist:
        st.info("No attacks detected yet")
        return
    
    # Create pie chart
    fig = go.Figure(data=[go.Pie(
        labels=list(attack_dist.keys()),
        values=list(attack_dist.values()),
        hole=0.3,
        marker=dict(colors=['#FF6B6B', '#FFC93B', '#4D96FF', '#6BCB77'])
    )])
    
    fig.update_layout(
        title="Attack Distribution (Donut Chart)",
        template='plotly_dark',
        height=400,
        margin=dict(l=0, r=0, t=30, b=0)
    )
    
    st.plotly_chart(fig, use_container_width=True)


def render_live_alerts():
    """Render live alerts log"""
    state = st.session_state.dashboard_state
    
    if not state.alerts:
        st.info("No alerts yet. System is clean.")
        return
    
    # Convert to DataFrame
    alerts_list = []
    for alert in state.alerts:
        alerts_list.append({
            'Timestamp': alert['timestamp'].strftime('%H:%M:%S'),
            'Source IP': alert.get('src_ip', 'unknown'),
            'Dest IP': alert.get('dst_ip', 'unknown'),
            'Protocol': alert.get('protocol', 'unknown'),
            'Attack Type': alert.get('attack_type', 'Unknown'),
            'Confidence': f"{alert.get('confidence', 0):.2%}",
        })
    
    # Display as table
    df_alerts = pd.DataFrame(alerts_list)
    
    # Color-code by attack type
    st.dataframe(
        df_alerts,
        use_container_width=True,
        height=300
    )


def render_sidebar_controls():
    """Render sidebar controls"""
    st.sidebar.markdown("### ⚙️ Configuration")
    
    # Auto-block toggle
    st.session_state.auto_block_enabled = st.sidebar.checkbox(
        "🔒 Auto-Block Attacks",
        value=st.session_state.auto_block_enabled
    )
    
    # Confidence threshold slider
    st.session_state.confidence_threshold = st.sidebar.slider(
        "Confidence Threshold",
        min_value=0.5,
        max_value=1.0,
        value=st.session_state.confidence_threshold,
        step=0.05,
        help="Only flag attacks if confidence exceeds this threshold"
    )
    
    # Stats section
    st.sidebar.markdown("### 📊 Statistics")
    state = st.session_state.dashboard_state
    
    st.sidebar.metric("Total Packets Seen", state.stats['total_packets'])
    st.sidebar.metric("Total Attacks", state.stats['total_attacks'])
    st.sidebar.metric("Unique IPs Blocked", len(state.stats['blocked_ips']))
    
    # Clear data button
    if st.sidebar.button("🗑️ Clear All Data"):
        st.session_state.dashboard_state = DashboardState()
        st.rerun()


def main():
    """Main dashboard function"""
    initialize_session()
    
    # Header
    st.markdown("# 🛡️ IDS/IPS Dashboard")
    st.markdown("Real-time Detection & Prevention System for DoS/DDoS Attacks")
    st.divider()
    
    # Render sidebar
    render_sidebar_controls()
    
    # Main content
    render_header()
    st.divider()
    
    # Metrics row
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📈 Live Traffic Graph")
        render_live_traffic_graph()
    
    with col2:
        st.markdown("### 🎯 Attack Distribution")
        render_attack_distribution()
    
    st.divider()
    
    # Alerts section
    st.markdown("### 🚨 Live Alerts Log")
    render_live_alerts()
    
    # Footer
    st.divider()
    state = st.session_state.dashboard_state
    col1, col2, col3 = st.columns(3)
    with col1:
        st.caption(f"Auto-Block: {'Enabled' if st.session_state.auto_block_enabled else 'Disabled'}")
    with col2:
        st.caption(f"Threshold: {st.session_state.confidence_threshold:.0%}")
    with col3:
        st.caption(f"Last Update: {datetime.now().strftime('%H:%M:%S')}")
    
    # Auto-refresh
    st.markdown("<script>setTimeout(function(){location.reload()}, 5000);</script>", 
               unsafe_allow_html=True)


if __name__ == "__main__":
    main()
