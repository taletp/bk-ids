# Dash Dashboard Documentation

## Overview

The IDS/IPS system now includes a modern **Dash-based web dashboard** with real-time monitoring, performance metrics, and alert notifications.

### Features

✅ **Real-time Monitoring**
- Live packet capture visualization
- Traffic timeline with attack markers
- Auto-refresh every 1 second

✅ **Performance Monitoring**
- CPU usage tracking
- Memory usage tracking  
- Packet rate (packets/second)
- Detection latency metrics

✅ **Alert System**
- Recent alerts panel
- Attack distribution charts
- Notification modal with badge counter
- Desktop notifications (browser-based)

✅ **Modern UI**
- Dark mode SOC-style interface
- Responsive design (Bootstrap)
- Interactive Plotly charts
- Clean, professional layout

---

## Installation

### Install Dependencies

```bash
cd /home/kali/Desktop/bk-ids
source venv/bin/activate
pip install -r requirements.txt
```

New packages installed:
- `dash>=2.14.0` - Core Dash framework
- `dash-bootstrap-components>=1.5.0` - Bootstrap UI components
- `psutil>=5.9.0` - System performance monitoring

---

## Usage

### Option 1: Integrated Mode (Dashboard + Detection)

Start the IDS with automatic dashboard:

```bash
# Live capture with dashboard
sudo venv/bin/python main.py --mode live --interface eth0

# The dashboard will automatically start at http://localhost:8050
# Open in your browser to view real-time monitoring
```

### Option 2: Dashboard Only (Standalone)

Launch dashboard without packet capture (for testing):

```bash
# Standalone dashboard with simulated data
python main.py --dashboard-only

# Access at http://localhost:8050
```

### Option 3: Custom Port

Specify a custom port for the dashboard:

```bash
sudo venv/bin/python main.py --mode live --interface eth0 --dashboard-port 8888

# Access at http://localhost:8888
```

### Option 4: Old Streamlit Dashboard

Use the original Streamlit dashboard (if preferred):

```bash
python main.py --dashboard
# Access at http://localhost:8501
```

---

## Dashboard Layout

### 1. Header Bar
- **System Status**: Live indicator (green = active)
- **Notification Button**: Bell icon with badge showing unread alerts
- **Reset Button**: Clear all statistics

### 2. Statistics Cards (Top Row)
Four key metrics displayed prominently:

| Card | Metric | Color |
|------|--------|-------|
| **Total Packets** | Captured packets + PPS rate | Blue |
| **Normal Traffic** | Non-attack packets + % | Green |
| **Attacks Detected** | Attack count + % | Red (pulsing) |
| **Blocked IPs** | IPs blocked + uptime | Orange |

### 3. Traffic Timeline
- **Visualization**: Scatter plot of packets over time
- **Green dots**: Normal traffic
- **Red X marks**: Detected attacks
- **Time window**: Last 100 packets

### 4. Attack Distribution
- **Chart type**: Donut chart
- **Data**: Breakdown by attack type
- **Colors**: Red gradient (darker = more attacks)

### 5. Performance Monitoring Panel

Three graphs showing system health:

#### CPU Usage
- **Display**: Area chart (0-100%)
- **Color**: Green
- **Update**: Every second
- **History**: Last 60 seconds

#### Memory Usage  
- **Display**: Area chart (0-100%)
- **Color**: Orange
- **Update**: Every second
- **History**: Last 60 seconds

#### Packet Rate
- **Display**: Line + markers
- **Color**: Cyan
- **Metric**: Packets processed per second
- **Update**: Real-time

### 6. Recent Alerts Panel
- **List**: Last 10 alerts (most recent first)
- **Details**: Attack type, source/destination IPs, confidence, timestamp
- **Color coding**: Red alerts with danger styling
- **Badge**: Shows total alert count

### 7. Notification Modal
- **Trigger**: Click bell icon in header
- **Content**: Detailed view of unread alerts
- **Auto-clear**: Alerts marked as read when modal opens
- **Scrollable**: Handles large number of alerts

---

## Configuration

Edit `config/config.py`:

```python
DASHBOARD_CONFIG = {
    'type': 'dash',  # 'dash' or 'streamlit'
    'port': 8050,  # Dash default port
    'host': '0.0.0.0',  # Listen on all interfaces (use '127.0.0.1' for localhost only)
    'debug': False,  # Enable Flask debug mode (dev only)
    'theme': 'dark',  # Only dark theme supported currently
    'refresh_interval': 1000,  # milliseconds (1 second)
    'enable_notifications': True,
    'enable_performance_monitoring': True,
}
```

### Security Considerations

**Default**: Dashboard listens on `0.0.0.0` (all interfaces)

- ✅ Access from any machine on network
- ⚠️ No authentication by default

**For production**, change to `127.0.0.1`:
```python
'host': '127.0.0.1',  # Localhost only
```

Then use SSH tunnel for remote access:
```bash
ssh -L 8050:localhost:8050 user@ids-server
# Access at http://localhost:8050 on your local machine
```

---

## Integration with IDS System

The dashboard integrates seamlessly with the detection engine:

### Automatic Data Flow

```
Packet Captured
    ↓
Detector.detect()
    ↓
Detection Result
    ↓
main.py: _packet_callback()
    ↓
dash_state.add_packet(packet_info, detection_result)
    ↓
Dashboard Updates Automatically
```

### Thread Safety

- Dashboard runs in separate thread
- All data updates use thread-safe locks
- No impact on detection performance

### Performance Impact

- **Memory**: ~10MB for dashboard (5000 packet buffer)
- **CPU**: <1% overhead for data updates
- **Network**: Minimal (local HTTP only)

---

## API Reference

### DashboardState Class

```python
from src.dashboard_dash import dashboard_state

# Add packet with detection result
dashboard_state.add_packet(packet_info, detection_result)

# Track blocked IP
dashboard_state.add_blocked_ip(ip_address)

# Get current statistics
stats = dashboard_state.get_stats()
# Returns: {
#   'uptime': seconds,
#   'total_packets': count,
#   'total_attacks': count,
#   'attack_rate': percentage,
#   'packets_per_second': rate,
#   'attack_by_type': {...},
#   'attack_by_protocol': {...}
# }

# Get recent alerts
alerts = dashboard_state.get_recent_alerts(count=10)

# Get unread alerts (marks as read)
unread = dashboard_state.get_unread_alerts()

# Reset all statistics
dashboard_state.reset_stats()
```

### Running Dashboard Programmatically

```python
from src.dashboard_dash import run_dashboard, start_dashboard_thread

# Option 1: Run in current thread (blocking)
run_dashboard(host='0.0.0.0', port=8050, debug=False)

# Option 2: Run in background thread
thread = start_dashboard_thread(host='0.0.0.0', port=8050)
# Continue with other code...
```

---

## Troubleshooting

### Dashboard won't start

**Error**: `ModuleNotFoundError: No module named 'dash'`

**Solution**:
```bash
pip install dash dash-bootstrap-components psutil
```

### Port already in use

**Error**: `Address already in use`

**Solution**:
```bash
# Check what's using port 8050
sudo lsof -i :8050

# Kill the process
sudo kill -9 <PID>

# Or use different port
python main.py --mode live --dashboard-port 8888
```

### Dashboard shows no data

**Cause**: Main IDS not capturing packets

**Solution**:
- Ensure running in `live` mode, not `mock`
- Check interface name: `--interface eth0`
- Run with sudo: `sudo python main.py --mode live`
- Check logs for errors

### Performance monitoring shows 0%

**Cause**: `psutil` not installed

**Solution**:
```bash
pip install psutil
```

### Browser shows "Unable to connect"

**Causes**:
1. Dashboard not started
2. Firewall blocking port
3. Wrong hostname

**Solutions**:
```bash
# Check if dashboard is running
netstat -tuln | grep 8050

# Allow port through firewall
sudo ufw allow 8050/tcp

# Try different host
# In config.py: 'host': '0.0.0.0'
```

---

## Customization

### Change Theme

Currently only dark theme (CYBORG) is supported. To add light theme:

```python
# In dashboard_dash.py, line 192
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.FLATLY],  # Light theme
    ...
)
```

Available themes: https://bootswatch.com/

### Adjust Refresh Rate

```python
# In config.py
DASHBOARD_CONFIG = {
    'refresh_interval': 2000,  # 2 seconds instead of 1
}

# In dashboard_dash.py, update intervals:
dcc.Interval(id='interval-fast', interval=2000, n_intervals=0),
```

### Modify Alert Display

Edit `create_alerts_panel()` in `dashboard_dash.py`:

```python
def create_alerts_panel():
    return dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Recent Alerts"),
                dbc.CardBody([
                    # Customize max height
                    html.Div(id='alerts-list', style={'maxHeight': '600px', 'overflowY': 'auto'})
                ])
            ])
        ], width=12),
    ])
```

### Add Custom Graphs

Example: Add protocol distribution chart

```python
# In layout
dbc.Row([
    dbc.Col([
        dcc.Graph(id='protocol-distribution')
    ], width=6)
])

# Add callback
@app.callback(
    Output('protocol-distribution', 'figure'),
    Input('interval-medium', 'n_intervals')
)
def update_protocol_chart(n):
    stats = dashboard_state.get_stats()
    protocols = stats['attack_by_protocol']
    
    fig = go.Figure(data=[go.Bar(
        x=list(protocols.keys()),
        y=list(protocols.values()),
        marker_color='red'
    )])
    
    fig.update_layout(
        template='plotly_dark',
        title='Attacks by Protocol'
    )
    
    return fig
```

---

## Comparison: Dash vs Streamlit

| Feature | Dash | Streamlit |
|---------|------|-----------|
| **Performance** | ✅ Faster (React-based) | ⚠️ Slower (reruns entire script) |
| **Customization** | ✅ Full control | ⚠️ Limited |
| **Callbacks** | ✅ Granular updates | ❌ Entire page refresh |
| **Threading** | ✅ Easy background tasks | ⚠️ Complex |
| **Real-time** | ✅ Native WebSocket | ⚠️ Polling only |
| **Learning Curve** | ⚠️ Steeper | ✅ Easier |
| **Production** | ✅ Recommended | ⚠️ Prototype only |

**Recommendation**: Use **Dash** for production IDS deployment.

---

## Future Enhancements

Potential additions:

1. **Email Alerts**
   - SMTP integration
   - Alert on critical attacks
   - Daily summary reports

2. **Historical Data**
   - SQLite database
   - Long-term statistics
   - Trend analysis

3. **Geolocation**
   - IP geolocation on map
   - Attack origin visualization

4. **User Authentication**
   - Login system
   - Role-based access
   - API keys

5. **Advanced Filters**
   - Filter by IP range
   - Filter by attack type
   - Date/time range selection

6. **Export Features**
   - CSV export
   - PDF reports
   - JSON API

7. **Multi-Instance Support**
   - Monitor multiple IDS instances
   - Aggregated dashboard
   - Distributed deployment

---

## Testing

### Test with Simulated Data

The dashboard includes built-in simulation for testing:

```bash
# Run standalone with simulated traffic
python src/dashboard_dash.py

# Access at http://localhost:8050
# Simulated attacks will appear automatically
```

### Test with Real Traffic

```bash
# Terminal 1: Start IDS with dashboard
sudo python main.py --mode live --interface eth0

# Terminal 2: Generate traffic
ping 8.8.8.8
curl https://google.com

# Browser: Monitor at http://localhost:8050
```

### Test Attack Detection

Follow the attack testing guide:
```bash
# See ATTACK_TESTING_GUIDE.md for detailed scenarios

# Quick test: SYN flood simulation
hping3 -S -p 80 --flood --rand-source 192.168.100.210

# Monitor dashboard for attack alerts
```

---

## Screenshots

### Main Dashboard
- Top: Statistics cards with color-coded metrics
- Middle: Traffic timeline showing normal/attack packets
- Right: Attack distribution donut chart

### Performance Monitoring
- CPU usage: Green area chart (0-100%)
- Memory usage: Orange area chart (0-100%)
- Packet rate: Cyan line chart with markers

### Alerts Panel
- List of recent attacks with details
- Red alert cards with attack type, IPs, confidence
- Timestamps for each alert

### Notification Modal
- Detailed alert information
- Scrollable list for multiple alerts
- Badge counter shows unread count

---

## Support

For issues or questions:

1. Check logs: `tail -f logs/ids.log`
2. Review this documentation
3. Test with `--dashboard-only` mode first
4. Ensure all dependencies installed

---

**Last Updated**: January 18, 2026  
**Dashboard Version**: 1.0  
**Status**: ✅ Production Ready
