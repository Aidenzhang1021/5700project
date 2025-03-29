import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import time
from datetime import datetime, timedelta
import threading
import queue

# Import functionality from other layers
from data_layer import capture_traffic, packet_callback, extract_ddos_features
from ai_layer import train_isolation_forest, detect_anomalies, analyze_ddos_threats

# Create global variables for sharing data between threads
traffic_data = []
latest_features = pd.DataFrame()
latest_anomalies = pd.DataFrame()
threat_analysis = {"detected_ddos": False, "message": "No data analyzed yet", "risk_level": "None"}
data_queue = queue.Queue()
stop_thread = threading.Event()

def monitor_traffic_thread():
    """Background thread for continuous capture and analysis of network traffic"""
    global traffic_data, latest_features, latest_anomalies, threat_analysis
    
    # Initialize model
    model = None
    feature_cols = None
    
    while not stop_thread.is_set():
        try:
            # Capture a batch of packets
            packets = capture_traffic(count=20)  # Capture 20 packets each time
            
            # Process packets
            new_packets = []
            for packet in packets:
                processed_packet = packet_callback(packet)
                if processed_packet:
                    new_packets.append(processed_packet)
            
            # Add to global data
            if new_packets:
                traffic_data.extend(new_packets)
                
                # Keep dataset size manageable (retain the most recent 10000 packets)
                if len(traffic_data) > 10000:
                    traffic_data = traffic_data[-10000:]
                
                # Extract features
                if len(traffic_data) > 10:  # Ensure sufficient data
                    # Process only recent data (sliding window)
                    window_size = 300  # Data within 5 minutes
                    current_time = time.time()
                    window_data = [p for p in traffic_data if p['timestamp'] > current_time - window_size]
                    
                    features = extract_ddos_features(window_data)
                    if not features.empty:
                        latest_features = features
                        
                        # Retrain model if it's empty or data grows significantly
                        if model is None or len(features) > 100 and len(features) % 100 == 0:
                            model, feature_cols = train_isolation_forest(features)
                        
                        # Detect anomalies
                        if model is not None:
                            results = detect_anomalies(model, features, feature_cols)
                            latest_anomalies = results[results['is_anomaly'] == -1].copy()
                            
                            # Analyze DDoS threats
                            threat_analysis = analyze_ddos_threats(results)
                            
                            # Put data in queue for UI use
                            data_queue.put({
                                'features': features,
                                'anomalies': latest_anomalies,
                                'threat_analysis': threat_analysis,
                                'traffic_stats': {
                                    'packet_count': len(window_data),
                                    'protocol_stats': pd.Series([p['protocol'] for p in window_data]).value_counts().to_dict(),
                                    'traffic_rate': features['Flow Bytes/s'].mean() if 'Flow Bytes/s' in features.columns else 0,
                                    'raw_packet_count': len(new_packets)  # Add raw packet count
                                }
                            })
            
            time.sleep(2)  # Control capture frequency
            
        except Exception as e:
            print(f"Error in monitoring thread: {e}")
            time.sleep(5)  # Wait longer after an error

def create_dashboard(use_external_data=False):
    st.set_page_config(page_title="AI-Powered Network Traffic Analyzer", layout="wide")
    
    st.title("AI-Powered Network Traffic Analyzer")
    
    # Initialize session state
    if 'traffic_chart_data' not in st.session_state:
        st.session_state.traffic_chart_data = pd.DataFrame({'packets': [0]})
        st.session_state.last_update_time = time.time()
        st.session_state.traffic_history = []  # Add traffic history
    
    # Sidebar configuration
    st.sidebar.header("Control Panel")
    
    monitor_active = st.sidebar.checkbox("Start Real-time Monitoring", value=True)
    
    protocol_filter = st.sidebar.multiselect(
        "Select Protocols to Filter",
        ["TCP", "UDP", "ICMP", "HTTP", "All"],
        default=["All"]
    )
    
    alert_threshold = st.sidebar.slider("Alert Sensitivity", 0.0, 1.0, 0.7)
    
    # Start internal monitoring thread only when not using external data
    if monitor_active and not use_external_data:
        if stop_thread.is_set():
            stop_thread.clear()
            monitoring_thread = threading.Thread(target=monitor_traffic_thread)
            monitoring_thread.daemon = True
            monitoring_thread.start()
            st.sidebar.success("Monitoring started")
    else:
        if not use_external_data:
            stop_thread.set()
            st.sidebar.warning("Monitoring stopped")
    
    # Main interface layout
    col1, col2 = st.columns(2)
    
    # Real-time traffic monitoring
    with col1:
        st.subheader("Real-time Traffic Monitoring")
        
        # Create an empty chart container - modified to use st.empty() instead of directly creating a chart
        traffic_chart_container = st.empty()
        
        # Create a metrics row
        metrics_cols = st.columns(3)
        packet_counter = metrics_cols[0].empty()
        bytes_rate = metrics_cols[1].empty()
        anomaly_counter = metrics_cols[2].empty()
    
    # Protocol distribution
    with col2:
        st.subheader("Protocol Distribution")
        protocol_chart_placeholder = st.empty()
    
    # Alert area
    st.subheader("Security Alerts")
    alert_box = st.empty()
    alerts_container = st.container()
    
    # DDoS Threat Analysis
    st.subheader("DDoS Threat Analysis")
    threat_container = st.container()
    with threat_container:
        threat_status = st.empty()
        threat_details = st.empty()
    
    # Traffic Analysis
    st.subheader("Traffic Analysis")
    traffic_tabs = st.tabs(["Flow Statistics", "Anomaly Details", "Protocol Analysis"])
    
    with traffic_tabs[0]:
        flow_stats_container = st.empty()
    
    with traffic_tabs[1]:
        anomaly_container = st.empty()
    
    with traffic_tabs[2]:
        protocol_details = st.empty()
    
    # Historical report section
    st.subheader("Historical Reports")
    report_col1, report_col2 = st.columns(2)
    
    with report_col1:
        report_type = st.selectbox("Report Type", ["Daily Report", "Weekly Report", "Monthly Report"])
    
    with report_col2:
        time_range = st.radio("Time Range", ["Last 24 Hours", "Last Week", "Custom Range"])
    
    if time_range == "Custom Range":
        date_col1, date_col2 = st.columns(2)
        with date_col1:
            start_date = st.date_input("Start Date", datetime.now() - timedelta(days=7))
        with date_col2:
            end_date = st.date_input("End Date", datetime.now())
    
    if st.button("Generate Report"):
        with st.spinner("Generating report..."):
            time.sleep(2)  # Simulate report generation
            st.success("Report generated successfully!")
            st.download_button(
                "Download PDF Report",
                "Report content would be generated here in a real implementation",
                file_name=f"network_report_{datetime.now().strftime('%Y%m%d')}.pdf"
            )
    
    # UI update loop
    update_interval = 1  # seconds - reduce update interval for smoother charts
    
    # Initialize data buffer for line chart
    if 'packet_rate_buffer' not in st.session_state:
        st.session_state.packet_rate_buffer = []
    
    protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0, "Other": 0}
    last_packet_count = 0
    
    while monitor_active:
        # Timer for chart updates
        current_time = time.time()
        time_diff = current_time - st.session_state.last_update_time
        
        # Check for new data
        new_data_available = False
        
        try:
            while not data_queue.empty():
                data = data_queue.get(block=False)
                new_data_available = True
                
                # Update metrics
                packet_counter.metric("Packets", data['traffic_stats']['packet_count'], 
                                    delta=data['traffic_stats']['packet_count'] - last_packet_count if last_packet_count > 0 else None)
                last_packet_count = data['traffic_stats']['packet_count']
                
                bytes_rate.metric("Traffic Rate", f"{data['traffic_stats']['traffic_rate']:.2f} B/s")
                
                anomaly_count = len(data['anomalies'])
                anomaly_counter.metric("Anomalies", anomaly_count)
                
                # Update protocol distribution
                for protocol, count in data['traffic_stats']['protocol_stats'].items():
                    protocol_counts[protocol] = protocol_counts.get(protocol, 0) + count
                
                # Keep only protocols with values
                filtered_protocols = {k: v for k, v in protocol_counts.items() if v > 0}
                
                if filtered_protocols:
                    fig, ax = plt.subplots()
                    wedges, texts, autotexts = ax.pie(
                        filtered_protocols.values(), 
                        labels=filtered_protocols.keys(),
                        autopct='%1.1f%%'
                    )
                    protocol_chart_placeholder.pyplot(fig)
                
                # Update traffic chart data - add packet count
                if 'raw_packet_count' in data['traffic_stats']:
                    # Add some random fluctuation for testing
                    packet_count = data['traffic_stats']['raw_packet_count']
                    # If data is all zeros, add random values for testing
                    if packet_count == 0:
                        packet_count = np.random.randint(1, 10)  # Random value between 1-10
                    
                    # Add to history
                    if 'traffic_history' not in st.session_state:
                        st.session_state.traffic_history = []
                    
                    st.session_state.traffic_history.append({
                        'time': current_time,
                        'bytes_rate': data['traffic_stats']['traffic_rate'],
                        'packets': packet_count
                    })
                    
                    # Limit history size
                    if len(st.session_state.traffic_history) > 100:
                        st.session_state.traffic_history = st.session_state.traffic_history[-100:]
                    
                    # Create chart data
                    chart_data = pd.DataFrame(st.session_state.traffic_history)
                    
                    if not chart_data.empty and len(chart_data) > 1:
                        # Use line_chart instead of add_rows
                        traffic_chart_container.line_chart(
                            chart_data, 
                            y='bytes_rate',
                            use_container_width=True
                        )
                    
                    # Update other UI elements
                    if 'anomalies' in data:
                        anomaly_count = len(data['anomalies'])
                        anomaly_counter.metric("Anomalies", anomaly_count)
                        
                        # Update alerts
                        if not data['anomalies'].empty and anomaly_count > 0:
                            # Filter alerts based on threshold
                            high_risk_anomalies = data['anomalies'][data['anomalies']['risk_score'] >= alert_threshold]
                            
                            with alerts_container:
                                for _, anomaly in high_risk_anomalies.iterrows():
                                    if 'risk_score' in anomaly and 'src_ip' in anomaly and 'dst_ip' in anomaly:
                                        st.warning(f"Suspicious traffic detected: {anomaly['src_ip']} → {anomaly['dst_ip']} - Risk score: {anomaly['risk_score']:.2f}")
                    
                    # Update protocol distribution
                    if 'traffic_stats' in data and 'protocol_stats' in data['traffic_stats']:
                        protocol_counts = data['traffic_stats']['protocol_stats']
                        # Keep only protocols with values
                        filtered_protocols = {k: v for k, v in protocol_counts.items() if v > 0}
                        
                        if filtered_protocols:
                            fig, ax = plt.subplots()
                            wedges, texts, autotexts = ax.pie(
                                filtered_protocols.values(), 
                                labels=filtered_protocols.keys(),
                                autopct='%1.1f%%'
                            )
                            protocol_chart_placeholder.pyplot(fig)
                    
                    # Update threat analysis
                    if 'threat_analysis' in data:
                        threat_level = data['threat_analysis']['risk_level']
                        if threat_level == "High":
                            threat_status.error(f"⚠️ DDoS Attack Detected - Risk Level: {threat_level}")
                        elif threat_level == "Medium":
                            threat_status.warning(f"⚠️ Potential DDoS Activity - Risk Level: {threat_level}")
                        elif threat_level == "Low":
                            threat_status.info(f"ℹ️ Suspicious Activity - Risk Level: {threat_level}")
                        else:
                            threat_status.success("✓ Normal Network Traffic")
                        
                        threat_details.info(data['threat_analysis']['message'])
                    
                    # Update traffic statistics
                    if 'features' in data and not data['features'].empty:
                        cols_to_show = ['src_ip', 'dst_ip', 'protocol', 'Flow Packets/s', 'Flow Bytes/s', 'Flow IAT Mean']
                        available_cols = [col for col in cols_to_show if col in data['features'].columns]
                        
                        if available_cols:
                            flow_stats_container.dataframe(data['features'][available_cols].head(10))
                    
                    # Update anomaly details
                    if 'anomalies' in data and not data['anomalies'].empty:
                        cols_to_show = ['src_ip', 'dst_ip', 'protocol', 'Flow Packets/s', 'risk_score']
                        available_cols = [col for col in cols_to_show if col in data['anomalies'].columns]
                        
                        if available_cols:
                            anomaly_container.dataframe(
                                data['anomalies'][available_cols].sort_values('risk_score', ascending=False).head(10)
                            )
                        else:
                            anomaly_container.info("No anomalies detected")
                    
                    # Update protocol analysis
                    if 'traffic_stats' in data and 'protocol_stats' in data['traffic_stats']:
                        protocol_summary = pd.Series(data['traffic_stats']['protocol_stats']).reset_index()
                        protocol_summary.columns = ['Protocol', 'Count']
                        if not protocol_summary.empty:
                            protocol_details.bar_chart(protocol_summary.set_index('Protocol'))
                    
                    # Add data point to keep chart active even if no new data but time has passed
                    if not new_data_available and time_diff > 3:
                        # Add zero value data point
                        if 'traffic_history' not in st.session_state:
                            st.session_state.traffic_history = []
                        
                        st.session_state.traffic_history.append({
                            'time': current_time,
                            'bytes_rate': 0,
                            'packets': 0
                        })
                        
                        # Keep data size manageable
                        if len(st.session_state.traffic_history) > 100:
                            st.session_state.traffic_history = st.session_state.traffic_history[-100:]
                        
                        # Create chart data
                        chart_data = pd.DataFrame(st.session_state.traffic_history)
                        
                        if not chart_data.empty and len(chart_data) > 1:
                            # Use line_chart instead of add_rows
                            traffic_chart_container.line_chart(
                                chart_data, 
                                y='bytes_rate',
                                use_container_width=True
                            )
                        
                        st.session_state.last_update_time = current_time
                    
        except Exception as e:
            print(f"Error updating dashboard: {e}")
            import traceback
            traceback.print_exc()
        
        time.sleep(1)  # Update every second
        
        # Check if checkbox has been unchecked
        if not monitor_active:
            break

    # Start update thread
    if use_external_data:
        update_thread = threading.Thread(target=update_dashboard)
        update_thread.daemon = True
        update_thread.start()

if __name__ == "__main__":
    create_dashboard()