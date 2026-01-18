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
            body {
                background-color: #0a0e27;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            .attack-alert {
                animation: pulse 1s infinite;
            }
            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.6; }
                100% { opacity: 1; }
            }
            .notification-badge {
                position: absolute;
                top: -8px;
                right: -8px;
                background-color: #dc3545;
                color: white;
                border-radius: 50%;
                padding: 2px 6px;
                font-size: 10px;
                font-weight: bold;
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
                        html.I(className="fas fa-shield-alt", style={'fontSize': '24px', 'marginRight': '10px'}),
                        html.Span("IDS/IPS Security Dashboard", style={'fontSize': '20px', 'fontWeight': 'bold'})
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
                    html.H6("Total Packets", className='text-muted'),
                    html.H3(id='stat-total-packets', children='0', className='text-info'),
                    html.Small(id='stat-packets-per-sec', children='0 pps', className='text-muted')
                ])
            ], className='bg-dark border-info')
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H6("Normal Traffic", className='text-muted'),
                    html.H3(id='stat-normal-packets', children='0', className='text-success'),
                    html.Small(id='stat-normal-rate', children='0%', className='text-muted')
                ])
            ], className='bg-dark border-success')
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H6("Attacks Detected", className='text-muted'),
                    html.H3(id='stat-attacks', children='0', className='text-danger attack-alert'),
                    html.Small(id='stat-attack-rate', children='0%', className='text-muted')
                ])
            ], className='bg-dark border-danger')
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H6("Blocked IPs", className='text-muted'),
                    html.H3(id='stat-blocked-ips', children='0', className='text-warning'),
                    html.Small(id='stat-uptime', children='Uptime: 0s', className='text-muted')
                ])
            ], className='bg-dark border-warning')
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
            ], className='bg-dark')
        ], width=8),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Attack Distribution"),
                dbc.CardBody([
                    dcc.Graph(id='attack-distribution', config={'displayModeBar': False})
                ])
            ], className='bg-dark')
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
            ], className='bg-dark')
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
            ], className='bg-dark')
        ], width=12),
    ], className='mb-3')


# Create notification modal
notification_modal = dbc.Modal([
    dbc.ModalHeader(dbc.ModalTitle("🔔 Alert Notifications")),
    dbc.ModalBody(id='notification-modal-body'),
    dbc.ModalFooter(
        dbc.Button("Close", id='close-notification', className='ms-auto', n_clicks=0)
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
], fluid=True, className='p-3')


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
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            height=300,
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor='#333'),
            title="No data available"
        )
        return fig
    
    # Prepare data
    timestamps = [p['timestamp'] for p in packets]
    is_attack = [1 if p.get('is_attack') else 0 for p in packets]
    
    # Create figure
    fig = go.Figure()
    
    # Add normal traffic
    normal_times = [t for t, a in zip(timestamps, is_attack) if a == 0]
    fig.add_trace(go.Scatter(
        x=normal_times,
        y=[0] * len(normal_times),
        mode='markers',
        name='Normal',
        marker=dict(color='#00ff00', size=8, symbol='circle'),
        hovertemplate='Normal Traffic<br>%{x}<extra></extra>'
    ))
    
    # Add attacks
    attack_times = [t for t, a in zip(timestamps, is_attack) if a == 1]
    fig.add_trace(go.Scatter(
        x=attack_times,
        y=[1] * len(attack_times),
        mode='markers',
        name='Attack',
        marker=dict(color='#ff0000', size=12, symbol='x'),
        hovertemplate='ATTACK<br>%{x}<extra></extra>'
    ))
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=300,
        showlegend=True,
        legend=dict(x=0, y=1.1, orientation='h'),
        xaxis=dict(title='Time', showgrid=False),
        yaxis=dict(showticklabels=False, showgrid=False, range=[-0.5, 1.5]),
        margin=dict(l=40, r=40, t=40, b=40)
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
            paper_bgcolor='rgba(0,0,0,0)',
            height=300,
            title="No attacks detected"
        )
        return fig
    
    labels = list(attack_types.keys())
    values = list(attack_types.values())
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.4,
        marker=dict(colors=px.colors.sequential.Reds)
    )])
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        height=300,
        showlegend=True,
        legend=dict(orientation='v', x=1, y=0.5),
        margin=dict(l=20, r=20, t=40, b=20)
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
            line=dict(color='#00ff00', width=2),
            name='CPU %'
        ))
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=200,
        showlegend=False,
        xaxis=dict(showticklabels=False, showgrid=False),
        yaxis=dict(title='CPU %', showgrid=True, gridcolor='#333', range=[0, 100]),
        margin=dict(l=40, r=20, t=30, b=20),
        title='CPU Usage'
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
                    html.Strong(alert['attack_type'], className='text-danger'),
                    html.Br(),
                    html.Small(f"{alert['src_ip']}:{alert.get('src_port', '?')} → {alert['dst_ip']}:{alert.get('dst_port', '?')}")
                ], width=8),
                dbc.Col([
                    html.Div([
                        html.Strong(f"{alert['confidence']:.1%}", className='text-warning'),
                        html.Br(),
                        html.Small(alert_time, className='text-muted')
                    ], style={'textAlign': 'right'})
                ], width=4),
            ])
        ], color='danger', className='mb-2')
        
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
                                    html.H5(alert['attack_type'], className='text-danger'),
                                    html.P([
                                        html.Strong("Source: "), f"{alert['src_ip']}:{alert.get('src_port', '?')}",
                                        html.Br(),
                                        html.Strong("Destination: "), f"{alert['dst_ip']}:{alert.get('dst_port', '?')}",
                                        html.Br(),
                                        html.Strong("Protocol: "), alert.get('protocol', 'Unknown'),
                                        html.Br(),
                                        html.Strong("Confidence: "), f"{alert['confidence']:.2%}",
                                    ]),
                                    html.Small(alert_time, className='text-muted')
                                ])
                            ])
                        ])
                    ], className='mb-2', color='dark', outline=True)
                )
        else:
            modal_content = [html.P("No new alerts", className='text-muted')]
        
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
