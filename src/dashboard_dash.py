"""
Modern IDS/IPS Dashboard using Dash (Plotly Dash)
Features:
- Real-time monitoring with WebSocket updates
- Performance metrics tracking
- Alert notifications (desktop & email)
- Interactive charts and graphs
- Dark mode SOC-style interface
"""

import dash
from dash import dcc, html, Input, Output, State, ctx
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from collections import deque, defaultdict
import json
import logging
import threading
import time
import numpy as np
from pathlib import Path
import sys

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger(__name__)


class DashboardState:
    """Manage dashboard state with thread-safe operations"""
    
    def __init__(self, max_history: int = 5000):
        self.lock = threading.Lock()
        
        # Packet buffers
        self.packets_buffer = deque(maxlen=max_history)
        self.alerts = deque(maxlen=1000)
        self.recent_alerts = deque(maxlen=10)  # For notification panel
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_attacks': 0,
            'normal_packets': 0,
            'whitelisted_packets': 0,
            'blocked_packets': 0,
            'attack_by_type': defaultdict(int),
            'blocked_ips': set(),
            'attack_by_protocol': defaultdict(int),
        }
        
        # Performance metrics
        self.performance = {
            'packets_per_second': deque(maxlen=60),  # Last 60 seconds
            'detection_latency': deque(maxlen=100),  # Last 100 detections
            'cpu_usage': deque(maxlen=60),
            'memory_usage': deque(maxlen=60),
            'timestamps': deque(maxlen=60),
        }
        
        # Alerts for notifications
        self.unread_alerts = []
        
        self.start_time = datetime.now()
        self.last_packet_time = None
        self.packet_timestamps = deque(maxlen=100)
    
    def add_packet(self, packet_info: dict, detection_result: dict = None):
        """Add packet and detection result"""
        with self.lock:
            timestamp = datetime.now()
            
            packet_data = {
                'timestamp': timestamp,
                **packet_info
            }
            
            if detection_result:
                packet_data.update(detection_result)
            
            self.packets_buffer.append(packet_data)
            self.stats['total_packets'] += 1
            
            # Track packet rate
            self.packet_timestamps.append(timestamp)
            self.last_packet_time = timestamp
            
            # Update stats based on detection
            if detection_result:
                if detection_result.get('is_attack'):
                    self.stats['total_attacks'] += 1
                    attack_type = detection_result.get('attack_type', 'Unknown')
                    self.stats['attack_by_type'][attack_type] += 1
                    
                    protocol = packet_info.get('protocol', 'Unknown')
                    self.stats['attack_by_protocol'][protocol] += 1
                    
                    # Add to alerts
                    alert_data = {
                        'timestamp': timestamp,
                        'src_ip': packet_info.get('src_ip'),
                        'dst_ip': packet_info.get('dst_ip'),
                        'attack_type': attack_type,
                        'confidence': detection_result.get('confidence', 0),
                        'protocol': protocol,
                        'src_port': packet_info.get('src_port'),
                        'dst_port': packet_info.get('dst_port'),
                    }
                    self.alerts.append(alert_data)
                    self.recent_alerts.append(alert_data)
                    self.unread_alerts.append(alert_data)
                    
                elif detection_result.get('whitelisted'):
                    self.stats['whitelisted_packets'] += 1
                else:
                    self.stats['normal_packets'] += 1
    
    def update_performance(self, cpu: float, memory: float):
        """Update performance metrics"""
        with self.lock:
            timestamp = datetime.now()
            self.performance['timestamps'].append(timestamp)
            self.performance['cpu_usage'].append(cpu)
            self.performance['memory_usage'].append(memory)
            
            # Calculate packets per second
            if len(self.packet_timestamps) > 1:
                recent_packets = [t for t in self.packet_timestamps 
                                 if (timestamp - t).total_seconds() < 1]
                pps = len(recent_packets)
                self.performance['packets_per_second'].append(pps)
            else:
                self.performance['packets_per_second'].append(0)
    
    def add_blocked_ip(self, ip: str):
        """Track blocked IP"""
        with self.lock:
            self.stats['blocked_ips'].add(ip)
            self.stats['blocked_packets'] += 1
    
    def get_stats(self):
        """Get current statistics"""
        with self.lock:
            uptime = (datetime.now() - self.start_time).total_seconds()
            pps = len([t for t in self.packet_timestamps 
                      if (datetime.now() - t).total_seconds() < 1])
            
            return {
                'uptime': uptime,
                'total_packets': self.stats['total_packets'],
                'total_attacks': self.stats['total_attacks'],
                'normal_packets': self.stats['normal_packets'],
                'whitelisted_packets': self.stats['whitelisted_packets'],
                'blocked_packets': self.stats['blocked_packets'],
                'attack_rate': (self.stats['total_attacks'] / max(self.stats['total_packets'], 1)) * 100,
                'packets_per_second': pps,
                'blocked_ips_count': len(self.stats['blocked_ips']),
                'attack_by_type': dict(self.stats['attack_by_type']),
                'attack_by_protocol': dict(self.stats['attack_by_protocol']),
            }
    
    def get_recent_alerts(self, count: int = 10):
        """Get recent alerts"""
        with self.lock:
            return list(self.recent_alerts)[-count:]
    
    def get_unread_alerts(self):
        """Get unread alerts and mark as read"""
        with self.lock:
            alerts = list(self.unread_alerts)
            self.unread_alerts.clear()
            return alerts
    
    def reset_stats(self):
        """Reset statistics"""
        with self.lock:
            self.stats = {
                'total_packets': 0,
                'total_attacks': 0,
                'normal_packets': 0,
                'whitelisted_packets': 0,
                'blocked_packets': 0,
                'attack_by_type': defaultdict(int),
                'blocked_ips': set(),
                'attack_by_protocol': defaultdict(int),
            }
            self.start_time = datetime.now()


# Initialize global state
dashboard_state = DashboardState()


# Initialize Dash app with dark theme
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.CYBORG],  # Dark theme
    suppress_callback_exceptions=True,
    title="IDS/IPS Dashboard"
)

# Custom CSS for additional styling
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
            /* Base Dark Theme Variables */
            :root {
                --bg-primary: #0d1117;
                --bg-secondary: #161b22;
                --bg-card: #1c2128;
                --bg-card-hover: #212830;
                --text-primary: #f0f6fc;
                --text-secondary: #8b949e;
                --accent-cyan: #58a6ff;
                --accent-green: #3fb950;
                --accent-red: #f85149;
                --accent-yellow: #d29922;
                --accent-purple: #a371f7;
                --accent-orange: #db6d28;
                --border-color: #30363d;
                --gradient-primary: linear-gradient(135deg, #1f2937 0%, #111827 100%);
                --gradient-cyan: linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%);
                --gradient-red: linear-gradient(135deg, #f85149 0%, #da3633 100%);
                --gradient-green: linear-gradient(135deg, #3fb950 0%, #2ea043 100%);
                --shadow-card: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.15);
                --shadow-card-hover: 0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.2);
                --shadow-glow: 0 0 20px rgba(88, 166, 255, 0.3);
            }

            body {
                background: var(--bg-primary);
                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                color: var(--text-primary);
                min-height: 100vh;
            }

            /* Custom Scrollbar */
            ::-webkit-scrollbar {
                width: 8px;
                height: 8px;
            }
            ::-webkit-scrollbar-track {
                background: var(--bg-secondary);
            }
            ::-webkit-scrollbar-thumb {
                background: var(--border-color);
                border-radius: 4px;
            }
            ::-webkit-scrollbar-thumb:hover {
                background: var(--text-secondary);
            }

            /* Card Styling */
            .card {
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                box-shadow: var(--shadow-card);
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                backdrop-filter: blur(10px);
            }
            .card:hover {
                background: var(--bg-card-hover);
                box-shadow: var(--shadow-card-hover);
                border-color: var(--accent-cyan);
                transform: translateY(-2px);
            }
            .card-header {
                background: var(--bg-secondary);
                border-bottom: 1px solid var(--border-color);
                border-radius: 12px 12px 0 0;
                padding: 1rem 1.25rem;
                font-weight: 600;
                font-size: 0.95rem;
                letter-spacing: 0.5px;
                color: var(--text-primary);
            }

            /* Navbar Styling */
            .navbar {
                background: linear-gradient(180deg, rgba(22, 27, 34, 0.95) 0%, rgba(28, 33, 40, 0.95) 100%) !important;
                border-bottom: 1px solid var(--border-color);
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
                backdrop-filter: blur(10px);
            }
            .navbar-brand {
                font-weight: 700;
                font-size: 1.25rem;
                letter-spacing: 0.5px;
            }

            /* Button Styling */
            .btn {
                border-radius: 8px;
                font-weight: 500;
                padding: 0.5rem 1rem;
                transition: all 0.2s ease;
                border: none;
                font-size: 0.875rem;
            }
            .btn:hover {
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            }
            .btn-primary {
                background: var(--gradient-cyan);
                color: #ffffff;
            }
            .btn-danger {
                background: var(--gradient-red);
                color: #ffffff;
            }
            .btn-warning {
                background: linear-gradient(135deg, #d29922 0%, #b8880f 100%);
                color: #ffffff;
            }
            .btn-success {
                background: var(--gradient-green);
                color: #ffffff;
            }

            /* Alert Styling */
            .alert {
                border: 1px solid var(--border-color);
                border-radius: 10px;
                background: var(--bg-card);
                color: var(--text-primary);
                font-size: 0.875rem;
                box-shadow: var(--shadow-card);
            }
            .alert-danger {
                background: linear-gradient(135deg, rgba(248, 81, 73, 0.1) 0%, rgba(218, 54, 51, 0.1) 100%);
                border-left: 4px solid var(--accent-red);
            }
            .alert-success {
                background: linear-gradient(135deg, rgba(63, 185, 80, 0.1) 0%, rgba(46, 160, 67, 0.1) 100%);
                border-left: 4px solid var(--accent-green);
            }
            .alert-warning {
                background: linear-gradient(135deg, rgba(210, 153, 34, 0.1) 0%, rgba(184, 136, 15, 0.1) 100%);
                border-left: 4px solid var(--accent-yellow);
            }
            .alert-info {
                background: linear-gradient(135deg, rgba(88, 166, 255, 0.1) 0%, rgba(56, 139, 253, 0.1) 100%);
                border-left: 4px solid var(--accent-cyan);
            }

            /* Status Badge */
            .attack-alert {
                animation: pulse-red 1.5s ease-in-out infinite;
            }
            @keyframes pulse-red {
                0%, 100% {
                    opacity: 1;
                    text-shadow: 0 0 10px rgba(248, 81, 73, 0.5);
                }
                50% {
                    opacity: 0.7;
                    text-shadow: 0 0 20px rgba(248, 81, 73, 0.8);
                }
            }

            /* Notification Badge */
            .notification-badge {
                position: absolute;
                top: -8px;
                right: -8px;
                background: var(--gradient-red);
                color: white;
                border-radius: 50%;
                padding: 4px 7px;
                font-size: 11px;
                font-weight: 700;
                box-shadow: 0 2px 8px rgba(248, 81, 73, 0.5);
                animation: badge-pulse 2s ease-in-out infinite;
            }
            @keyframes badge-pulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.1); }
            }

            /* Live Status Indicator */
            #live-status {
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 6px 12px;
                background: rgba(63, 185, 80, 0.15);
                border-radius: 20px;
                border: 1px solid rgba(63, 185, 80, 0.3);
                font-weight: 600;
                font-size: 0.875rem;
            }
            #live-status i {
                width: 10px;
                height: 10px;
                background: var(--accent-green);
                border-radius: 50%;
                animation: status-pulse 2s ease-in-out infinite;
                box-shadow: 0 0 10px rgba(63, 185, 80, 0.6);
            }
            @keyframes status-pulse {
                0%, 100% {
                    transform: scale(1);
                    opacity: 1;
                }
                50% {
                    transform: scale(1.2);
                    opacity: 0.8;
                }
            }

            /* Stats Cards */
            .card-body h6 {
                color: var(--text-secondary);
                font-size: 0.8rem;
                font-weight: 500;
                text-transform: uppercase;
                letter-spacing: 0.75px;
                margin-bottom: 0.5rem;
            }
            .card-body h3 {
                font-weight: 700;
                font-size: 1.75rem;
                margin-bottom: 0.25rem;
            }
            .card-body small {
                font-size: 0.8rem;
                color: var(--text-secondary);
            }

            /* Text Colors */
            .text-cyan { color: var(--accent-cyan) !important; }
            .text-purple { color: var(--accent-purple) !important; }
            .text-orange { color: var(--accent-orange) !important; }

            /* Graph Container */
            .js-plotly-plot {
                border-radius: 8px;
            }
            .plotly .modebar {
                left: 50%;
                transform: translateX(-50%);
                background: rgba(22, 27, 34, 0.9) !important;
                border: 1px solid var(--border-color);
                border-radius: 8px;
                backdrop-filter: blur(10px);
            }

            /* Modal Styling */
            .modal-content {
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
            }
            .modal-header {
                border-bottom: 1px solid var(--border-color);
                background: var(--bg-secondary);
                border-radius: 12px 12px 0 0;
            }
            .modal-footer {
                border-top: 1px solid var(--border-color);
                background: var(--bg-secondary);
                border-radius: 0 0 12px 12px;
            }
            .modal-title {
                color: var(--text-primary);
                font-weight: 600;
            }

            /* Card Border Colors */
            .border-info {
                border-color: rgba(88, 166, 255, 0.3) !important;
                border-left: 4px solid var(--accent-cyan) !important;
            }
            .border-success {
                border-color: rgba(63, 185, 80, 0.3) !important;
                border-left: 4px solid var(--accent-green) !important;
            }
            .border-danger {
                border-color: rgba(248, 81, 73, 0.3) !important;
                border-left: 4px solid var(--accent-red) !important;
            }
            .border-warning {
                border-color: rgba(210, 153, 34, 0.3) !important;
                border-left: 4px solid var(--accent-yellow) !important;
            }

            /* Badge Styling */
            .badge {
                padding: 0.35rem 0.65rem;
                border-radius: 6px;
                font-weight: 600;
                font-size: 0.75rem;
            }

            /* Typography Enhancements */
            strong {
                color: var(--text-primary);
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''


# Layout components
def create_header():
    """Create dashboard header"""
    return dbc.Navbar(
        dbc.Container([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.I(className="fas fa-shield-alt", style={'fontSize': '24px', 'marginRight': '12px', 'color': '#58a6ff'}),
                        html.Span("IDS/IPS Security Dashboard", style={'fontSize': '20px', 'fontWeight': '700', 'color': '#f0f6fc'})
                    ], style={'display': 'flex', 'alignItems': 'center'})
                ], width=6),
                dbc.Col([
                    html.Div([
                        dbc.Button([
                            html.I(className="fas fa-bell", style={'marginRight': '5px'}),
                            html.Span(id='notification-badge', className='notification-badge', children='0', style={'display': 'none'})
                        ], id='notification-btn', color='warning', size='sm', className='me-2'),
                        dbc.Button([
                            html.I(className="fas fa-sync-alt", style={'marginRight': '5px'}),
                            "Reset"
                        ], id='reset-btn', color='danger', size='sm', className='me-2'),
                        html.Span(id='live-status', children=[
                            html.I(className="fas fa-circle", style={'color': '#00ff00', 'marginRight': '5px'}),
                            "LIVE"
                        ], style={'color': '#00ff00', 'fontWeight': 'bold', 'fontSize': '14px'})
                    ], style={'display': 'flex', 'justifyContent': 'flex-end', 'alignItems': 'center'})
                ], width=6),
            ], align='center', className='w-100'),
        ], fluid=True),
        color='dark',
        dark=True,
        className='mb-3'
    )


def create_stats_cards():
    """Create statistics cards"""
    return dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H6("Total Packets"),
                    html.H3(id='stat-total-packets', children='0', className='text-cyan'),
                    html.Small(id='stat-packets-per-sec', children='0 pps')
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H6("Normal Traffic"),
                    html.H3(id='stat-normal-packets', children='0', className='text-success'),
                    html.Small(id='stat-normal-rate', children='0%')
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H6("Attacks Detected"),
                    html.H3(id='stat-attacks', children='0', className='text-danger attack-alert'),
                    html.Small(id='stat-attack-rate', children='0%')
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H6("Blocked IPs"),
                    html.H3(id='stat-blocked-ips', children='0', className='text-orange'),
                    html.Small(id='stat-uptime', children='Uptime: 0s')
                ])
            ])
        ], width=3),
    ], className='mb-3')


def create_charts():
    """Create main charts"""
    return dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Traffic Timeline (Last 60s)"),
                dbc.CardBody([
                    dcc.Graph(id='traffic-timeline', config={'displayModeBar': False})
                ])
            ])
        ], width=8),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Attack Distribution"),
                dbc.CardBody([
                    dcc.Graph(id='attack-distribution', config={'displayModeBar': False})
                ])
            ])
        ], width=4),
    ], className='mb-3')


def create_performance_panel():
    """Create performance monitoring panel"""
    return dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("System Performance"),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            dcc.Graph(id='cpu-usage-graph', config={'displayModeBar': False})
                        ], width=6),
                        dbc.Col([
                            dcc.Graph(id='memory-usage-graph', config={'displayModeBar': False})
                        ], width=6),
                    ]),
                    dbc.Row([
                        dbc.Col([
                            dcc.Graph(id='packet-rate-graph', config={'displayModeBar': False})
                        ], width=12),
                    ], className='mt-2')
                ])
            ])
        ], width=12),
    ], className='mb-3')


def create_alerts_panel():
    """Create recent alerts panel"""
    return dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader([
                    html.Span("Recent Alerts", style={'marginRight': '10px'}),
                    dbc.Badge(id='alert-count-badge', children='0', color='danger', className='ms-2')
                ]),
                dbc.CardBody([
                    html.Div(id='alerts-list', style={'maxHeight': '400px', 'overflowY': 'auto'})
                ])
            ])
        ], width=12),
    ], className='mb-3')


# Create notification modal
notification_modal = dbc.Modal([
    dbc.ModalHeader(dbc.ModalTitle("🔔 Alert Notifications")),
    dbc.ModalBody(id='notification-modal-body'),
    dbc.ModalFooter(
        dbc.Button("Close", id='close-notification', className='ms-auto', n_clicks=0, color='secondary')
    )
], id='notification-modal', is_open=False, size='lg')


# Main layout
app.layout = dbc.Container([
    create_header(),
    create_stats_cards(),
    create_charts(),
    create_performance_panel(),
    create_alerts_panel(),
    notification_modal,

    # Interval components for auto-refresh
    dcc.Interval(id='interval-fast', interval=1000, n_intervals=0),  # 1 second
    dcc.Interval(id='interval-medium', interval=5000, n_intervals=0),  # 5 seconds

    # Store for notification count
    dcc.Store(id='notification-store', data={'count': 0}),
], fluid=True, style={'padding': '20px', 'maxWidth': '1400px'})


# Callbacks
@app.callback(
    [
        Output('stat-total-packets', 'children'),
        Output('stat-packets-per-sec', 'children'),
        Output('stat-normal-packets', 'children'),
        Output('stat-normal-rate', 'children'),
        Output('stat-attacks', 'children'),
        Output('stat-attack-rate', 'children'),
        Output('stat-blocked-ips', 'children'),
        Output('stat-uptime', 'children'),
    ],
    Input('interval-fast', 'n_intervals')
)
def update_stats(n):
    """Update statistics cards"""
    stats = dashboard_state.get_stats()
    
    uptime = int(stats['uptime'])
    hours = uptime // 3600
    minutes = (uptime % 3600) // 60
    seconds = uptime % 60
    uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    normal_rate = (stats['normal_packets'] / max(stats['total_packets'], 1)) * 100
    
    return (
        f"{stats['total_packets']:,}",
        f"{stats['packets_per_second']} pps",
        f"{stats['normal_packets']:,}",
        f"{normal_rate:.1f}%",
        f"{stats['total_attacks']:,}",
        f"{stats['attack_rate']:.1f}%",
        f"{stats['blocked_ips_count']}",
        f"Uptime: {uptime_str}"
    )


@app.callback(
    Output('traffic-timeline', 'figure'),
    Input('interval-fast', 'n_intervals')
)
def update_traffic_timeline(n):
    """Update traffic timeline chart"""
    with dashboard_state.lock:
        packets = list(dashboard_state.packets_buffer)[-100:]
    
    if not packets:
        # Empty chart
        fig = go.Figure()
        fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(28, 33, 40, 0.8)',
            plot_bgcolor='rgba(28, 33, 40, 0.8)',
            height=300,
            xaxis=dict(showgrid=False, color='#8b949e'),
            yaxis=dict(showgrid=True, gridcolor='#30363d', color='#8b949e'),
            title=dict(text='No data available', font=dict(color='#8b949e', size=14)),
            font=dict(color='#f0f6fc')
        )
        return fig
    
    # Prepare data
    timestamps = [p['timestamp'] for p in packets]
    is_attack = [1 if p.get('is_attack') else 0 for p in packets]
    
    # Create figure
    fig = go.Figure()
    
    # Add normal traffic with improved styling
    normal_times = [t for t, a in zip(timestamps, is_attack) if a == 0]
    if normal_times:
        fig.add_trace(go.Scatter(
            x=normal_times,
            y=[0] * len(normal_times),
            mode='markers',
            name='Normal',
            marker=dict(
                color='#3fb950',
                size=10,
                symbol='circle',
                line=dict(color='#2ea043', width=2),
                opacity=0.8
            ),
            hovertemplate='<b>Normal Traffic</b><br>Time: %{x}<extra></extra>',
            hoverlabel=dict(bgcolor='#1c2128', bordercolor='#3fb950', font_size=12)
        ))
    
    # Add attacks with enhanced styling
    attack_times = [t for t, a in zip(timestamps, is_attack) if a == 1]
    if attack_times:
        fig.add_trace(go.Scatter(
            x=attack_times,
            y=[1] * len(attack_times),
            mode='markers',
            name='Attack',
            marker=dict(
                color='#f85149',
                size=14,
                symbol='x',
                line=dict(color='#da3633', width=2),
                opacity=1.0
            ),
            hovertemplate='<b style="color:#f85149">⚠️ ATTACK</b><br>Time: %{x}<extra></extra>',
            hoverlabel=dict(bgcolor='#1c2128', bordercolor='#f85149', font_size=12)
        ))
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(28, 33, 40, 0.8)',
        plot_bgcolor='rgba(28, 33, 40, 0.8)',
        height=300,
        showlegend=True,
        legend=dict(
            x=0,
            y=1.1,
            orientation='h',
            bgcolor='rgba(28, 33, 40, 0.9)',
            bordercolor='#30363d',
            borderwidth=1,
            font=dict(size=11)
        ),
        xaxis=dict(
            title='Time',
            showgrid=False,
            color='#8b949e',
            gridcolor='#30363d',
            title_font=dict(size=12)
        ),
        yaxis=dict(
            showticklabels=False,
            showgrid=False,
            range=[-0.5, 1.5],
            color='#8b949e'
        ),
        margin=dict(l=40, r=40, t=50, b=40),
        font=dict(color='#f0f6fc')
    )
    
    return fig


@app.callback(
    Output('attack-distribution', 'figure'),
    Input('interval-medium', 'n_intervals')
)
def update_attack_distribution(n):
    """Update attack distribution pie chart"""
    stats = dashboard_state.get_stats()
    attack_types = stats['attack_by_type']
    
    if not attack_types:
        # Empty chart
        fig = go.Figure()
        fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(28, 33, 40, 0.8)',
            plot_bgcolor='rgba(28, 33, 40, 0.8)',
            height=300,
            title=dict(text='No attacks detected', font=dict(color='#8b949e', size=14)),
            font=dict(color='#f0f6fc')
        )
        return fig
    
    labels = list(attack_types.keys())
    values = list(attack_types.values())
    
    # Custom color palette for attack types (cybersecurity theme)
    colors = ['#f85149', '#db6d28', '#d29922', '#a371f7', '#58a6ff', '#3fb950']
    colors = colors[:len(labels)]
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.45,
        marker=dict(
            colors=colors,
            line=dict(color='#1c2128', width=2)
        ),
        textinfo='label+percent',
        textfont=dict(size=11, color='#f0f6fc'),
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>',
        hoverlabel=dict(bgcolor='#1c2128', bordercolor='#30363d', font_size=12)
    )])
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(28, 33, 40, 0.8)',
        plot_bgcolor='rgba(28, 33, 40, 0.8)',
        height=300,
        showlegend=True,
        legend=dict(
            orientation='v',
            x=1.02,
            y=0.5,
            bgcolor='rgba(28, 33, 40, 0.9)',
            bordercolor='#30363d',
            borderwidth=1,
            font=dict(size=10)
        ),
        margin=dict(l=20, r=120, t=40, b=20),
        font=dict(color='#f0f6fc')
    )
    
    return fig


@app.callback(
    Output('cpu-usage-graph', 'figure'),
    Input('interval-fast', 'n_intervals')
)
def update_cpu_usage(n):
    """Update CPU usage graph"""
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent
        dashboard_state.update_performance(cpu, memory)
    except ImportError:
        # If psutil not available, use dummy data
        cpu = 0
    
    with dashboard_state.lock:
        cpu_data = list(dashboard_state.performance['cpu_usage'])
        timestamps = list(dashboard_state.performance['timestamps'])
    
    fig = go.Figure()
    
    if cpu_data:
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=cpu_data,
            mode='lines',
            fill='tozeroy',
            line=dict(color='#58a6ff', width=2.5),
            name='CPU %',
            fillcolor='rgba(88, 166, 255, 0.15)'
        ))
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(28, 33, 40, 0.8)',
        plot_bgcolor='rgba(28, 33, 40, 0.8)',
        height=200,
        showlegend=False,
        xaxis=dict(
            showticklabels=False,
            showgrid=False,
            color='#8b949e'
        ),
        yaxis=dict(
            title='CPU %',
            showgrid=True,
            gridcolor='#30363d',
            range=[0, 100],
            color='#8b949e',
            title_font=dict(size=11)
        ),
        margin=dict(l=40, r=20, t=40, b=20),
        title=dict(text='CPU Usage', font=dict(size=13, color='#f0f6fc')),
        font=dict(color='#f0f6fc')
    )
    
    return fig


def update_memory_usage(n):
    """Update memory usage graph"""
    with dashboard_state.lock:
        memory_data = list(dashboard_state.performance['memory_usage'])
        timestamps = list(dashboard_state.performance['timestamps'])
    
    fig = go.Figure()
    
    if memory_data:
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=memory_data,
            mode='lines',
            fill='tozeroy',
            line=dict(color='#a371f7', width=2.5),
            name='Memory %',
            fillcolor='rgba(163, 113, 247, 0.15)'
        ))
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(28, 33, 40, 0.8)',
        plot_bgcolor='rgba(28, 33, 40, 0.8)',
        height=200,
        showlegend=False,
        xaxis=dict(
            showticklabels=False,
            showgrid=False,
            color='#8b949e'
        ),
        yaxis=dict(
            title='Memory %',
            showgrid=True,
            gridcolor='#30363d',
            range=[0, 100],
            color='#8b949e',
            title_font=dict(size=11)
        ),
        margin=dict(l=40, r=20, t=40, b=20),
        title=dict(text='Memory Usage', font=dict(size=13, color='#f0f6fc')),
        font=dict(color='#f0f6fc')
    )
    
    return fig


def update_packet_rate(n):
    """Update packet rate graph"""
    with dashboard_state.lock:
        pps_data = list(dashboard_state.performance['packets_per_second'])
        timestamps = list(dashboard_state.performance['timestamps'])
    
    fig = go.Figure()
    
    if pps_data:
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=pps_data,
            mode='lines+markers',
            line=dict(color='#3fb950', width=2.5),
            marker=dict(size=5, color='#3fb950'),
            name='Packets/sec',
            hovertemplate='<b>Packets/sec</b><br>Time: %{x}<br>Rate: %{y}<extra></extra>',
            hoverlabel=dict(bgcolor='#1c2128', bordercolor='#3fb950', font_size=12)
        ))
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(28, 33, 40, 0.8)',
        plot_bgcolor='rgba(28, 33, 40, 0.8)',
        height=200,
        showlegend=False,
        xaxis=dict(
            title='Time',
            showgrid=False,
            color='#8b949e',
            title_font=dict(size=11)
        ),
        yaxis=dict(
            title='Packets/sec',
            showgrid=True,
            gridcolor='#30363d',
            color='#8b949e',
            title_font=dict(size=11)
        ),
        margin=dict(l=40, r=20, t=40, b=40),
        title=dict(text='Packet Rate', font=dict(size=13, color='#f0f6fc')),
        font=dict(color='#f0f6fc')
    )
    
    return fig


@app.callback(
    Output('memory-usage-graph', 'figure'),
    Input('interval-fast', 'n_intervals')
)
def update_memory_usage(n):
    """Update memory usage graph"""
    with dashboard_state.lock:
        memory_data = list(dashboard_state.performance['memory_usage'])
        timestamps = list(dashboard_state.performance['timestamps'])
    
    fig = go.Figure()
    
    if memory_data:
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=memory_data,
            mode='lines',
            fill='tozeroy',
            line=dict(color='#ff9900', width=2),
            name='Memory %'
        ))
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=200,
        showlegend=False,
        xaxis=dict(showticklabels=False, showgrid=False),
        yaxis=dict(title='Memory %', showgrid=True, gridcolor='#333', range=[0, 100]),
        margin=dict(l=40, r=20, t=30, b=20),
        title='Memory Usage'
    )
    
    return fig


@app.callback(
    Output('packet-rate-graph', 'figure'),
    Input('interval-fast', 'n_intervals')
)
def update_packet_rate(n):
    """Update packet rate graph"""
    with dashboard_state.lock:
        pps_data = list(dashboard_state.performance['packets_per_second'])
        timestamps = list(dashboard_state.performance['timestamps'])
    
    fig = go.Figure()
    
    if pps_data:
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=pps_data,
            mode='lines+markers',
            line=dict(color='#00ffff', width=2),
            marker=dict(size=4),
            name='Packets/sec'
        ))
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=200,
        showlegend=False,
        xaxis=dict(title='Time', showgrid=False),
        yaxis=dict(title='Packets/sec', showgrid=True, gridcolor='#333'),
        margin=dict(l=40, r=20, t=30, b=40),
        title='Packet Rate'
    )
    
    return fig


@app.callback(
    [Output('alerts-list', 'children'), Output('alert-count-badge', 'children')],
    Input('interval-fast', 'n_intervals')
)
def update_alerts_list(n):
    """Update recent alerts list"""
    alerts = dashboard_state.get_recent_alerts(10)
    
    if not alerts:
        return html.Div("No alerts yet", className='text-muted'), '0'
    
    alert_items = []
    for alert in reversed(alerts):  # Most recent first
        alert_time = alert['timestamp'].strftime('%H:%M:%S')
        
        alert_card = dbc.Alert([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.Strong(alert['attack_type']),
                        html.Small([
                            html.Span(style={'color': '#8b949e'}),
                            f" {alert['src_ip']}:{alert.get('src_port', '?')} → {alert['dst_ip']}:{alert.get('dst_port', '?')}"
                        ])
                    ], style={'marginBottom': '4px'})
                ], width=7),
                dbc.Col([
                    html.Div([
                        html.Strong(f"{alert['confidence']:.1%}", style={'color': '#d29922'}),
                        html.Small(alert_time, style={'color': '#8b949e'})
                    ], style={'textAlign': 'right'})
                ], width=5),
            ])
        ], color='danger', className='mb-2', style={'borderRadius': '8px'})
        
        alert_items.append(alert_card)
    
    return alert_items, str(len(alerts))


@app.callback(
    [
        Output('notification-modal', 'is_open'),
        Output('notification-modal-body', 'children'),
        Output('notification-badge', 'children'),
        Output('notification-badge', 'style'),
        Output('notification-store', 'data')
    ],
    [
        Input('notification-btn', 'n_clicks'),
        Input('close-notification', 'n_clicks'),
        Input('interval-fast', 'n_intervals')
    ],
    [State('notification-modal', 'is_open'), State('notification-store', 'data')]
)
def handle_notifications(notify_click, close_click, interval, is_open, store_data):
    """Handle notification modal"""
    triggered = ctx.triggered_id
    
    # Get unread alerts
    unread = dashboard_state.get_unread_alerts()
    unread_count = len(unread)
    
    # Update badge
    badge_style = {'display': 'inline'} if unread_count > 0 else {'display': 'none'}
    
    # Open modal on button click
    if triggered == 'notification-btn' and notify_click:
        modal_content = []
        
        if unread:
            for alert in reversed(unread[-10:]):  # Last 10
                alert_time = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                modal_content.append(
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    html.H5(alert['attack_type'], style={'color': '#f85149', 'marginBottom': '10px'}),
                                    html.P([
                                        html.Strong("Source: ", style={'color': '#f0f6fc'}), f"{alert['src_ip']}:{alert.get('src_port', '?')}",
                                        html.Br(),
                                        html.Strong("Destination: ", style={'color': '#f0f6fc'}), f"{alert['dst_ip']}:{alert.get('dst_port', '?')}",
                                        html.Br(),
                                        html.Strong("Protocol: ", style={'color': '#f0f6fc'}), alert.get('protocol', 'Unknown'),
                                        html.Br(),
                                        html.Strong("Confidence: ", style={'color': '#f0f6fc'}), f"{alert['confidence']:.2%}",
                                    ], style={'color': '#8b949e', 'marginBottom': '8px'}),
                                    html.Small(alert_time, style={'color': '#8b949e'})
                                ])
                            ])
                        ])
                    ], className='mb-2', color='dark', outline=True, style={'borderColor': '#30363d', 'borderRadius': '10px'})
                )
        else:
            modal_content = [html.P("No new alerts", style={'color': '#8b949e', 'textAlign': 'center', 'padding': '20px'})]
        
        return True, modal_content, '0', {'display': 'none'}, {'count': 0}
    
    # Close modal
    elif triggered == 'close-notification':
        return False, [], str(unread_count), badge_style, {'count': unread_count}
    
    # Update badge on interval
    else:
        return is_open, dash.no_update, str(unread_count), badge_style, {'count': unread_count}


@app.callback(
    Output('interval-fast', 'n_intervals'),
    Input('reset-btn', 'n_clicks'),
    prevent_initial_call=True
)
def reset_dashboard(n):
    """Reset dashboard statistics"""
    if n:
        dashboard_state.reset_stats()
    return 0


# Function to run dashboard
def run_dashboard(host='0.0.0.0', port=8050, debug=False):
    """Run the Dash dashboard"""
    logger.info(f"Starting Dash dashboard on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


# For integration with main.py
def start_dashboard_thread(host='0.0.0.0', port=8050):
    """Start dashboard in separate thread"""
    thread = threading.Thread(target=run_dashboard, args=(host, port), daemon=True)
    thread.start()
    return thread


if __name__ == '__main__':
    # Simulate some data for testing
    import random
    
    def simulate_traffic():
        """Simulate traffic for testing"""
        while True:
            # Generate random packet
            is_attack = random.random() < 0.1  # 10% attacks
            
            packet_info = {
                'src_ip': f"192.168.1.{random.randint(1, 254)}",
                'dst_ip': f"10.0.0.{random.randint(1, 254)}",
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 3389]),
                'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            }
            
            detection_result = {
                'is_attack': is_attack,
                'attack_type': random.choice(['SYN_Flood', 'UDP_Flood', 'Port_Scan']) if is_attack else 'Normal',
                'confidence': random.uniform(0.85, 0.99) if is_attack else random.uniform(0.1, 0.5),
            }
            
            dashboard_state.add_packet(packet_info, detection_result)
            
            if is_attack:
                dashboard_state.add_blocked_ip(packet_info['src_ip'])
            
            time.sleep(random.uniform(0.01, 0.1))
    
    # Start simulation in background
    sim_thread = threading.Thread(target=simulate_traffic, daemon=True)
    sim_thread.start()
    
    # Run dashboard
    run_dashboard(port=8050, debug=True)
