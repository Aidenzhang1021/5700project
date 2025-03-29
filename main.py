import threading
import time
import pandas as pd
import numpy as np
from data_layer import capture_traffic, packet_callback, extract_ddos_features
from ai_layer import train_isolation_forest, detect_anomalies, analyze_ddos_threats
from app_layer import create_dashboard, data_queue
import queue

# Global data store
traffic_data = []
anomalies = []
ddos_features = pd.DataFrame()
threat_analysis = {}
# Add variables for storing time series data
traffic_time_series = []
protocol_distribution = {}

def data_collection_thread():
    """Thread for continuous data collection"""
    global traffic_data, traffic_time_series, protocol_distribution
    
    # Add variables for calculating traffic rate
    last_time = time.time()
    last_bytes_total = 0
    bytes_total = 0
    
    while True:
        try:
            # Capture real-time traffic
            print("Starting to capture network traffic...")
            new_packets = capture_traffic(count=50)  # Using defined interface
            print(f"Captured {len(new_packets)} packets")
            
            # Process and store data
            processed_count = 0
            current_protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
            current_bytes = 0
            
            for packet in new_packets:
                processed_packet = packet_callback(packet)
                if processed_packet:
                    traffic_data.append(processed_packet)
                    processed_count += 1
                    current_bytes += processed_packet['size']  # Accumulate bytes
                    bytes_total += processed_packet['size']
                    
                    # Update protocol distribution
                    protocol = processed_packet['protocol']
                    current_protocols[protocol] = current_protocols.get(protocol, 0) + 1
            
            # Calculate traffic rate
            current_time = time.time()
            time_diff = current_time - last_time
            
            # Prevent division by zero
            if time_diff > 0:
                bytes_rate = (bytes_total - last_bytes_total) / time_diff
            else:
                bytes_rate = 0
                
            last_time = current_time
            last_bytes_total = bytes_total
            
            # Update time series data - record time points even if there are no packets
            traffic_time_series.append({
                'timestamp': current_time,
                'packet_count': processed_count,
                'bytes_rate': bytes_rate,
                'bytes': current_bytes
            })
            
            # Print time series data for debugging
            print(f"Added time series data point: time={current_time}, count={processed_count}, bytes_rate={bytes_rate:.2f} B/s")
            print(f"Time series data points: {len(traffic_time_series)}")
            
            # Limit the size of time series data
            if len(traffic_time_series) > 100:
                traffic_time_series = traffic_time_series[-100:]
            
            # Update protocol distribution
            protocol_distribution = current_protocols
            print(f"Protocol distribution: {protocol_distribution}")
            
            print(f"Currently processed {len(traffic_data)} packets")
            
            # Limit the size of traffic_data to control memory usage
            max_packets = 10000
            if len(traffic_data) > max_packets:
                traffic_data = traffic_data[-max_packets:]
            
            # Put data into queue for app_layer usage
            data_queue.put({
                'traffic_stats': {
                    'packet_count': len(traffic_data),
                    'protocol_stats': current_protocols,
                    'traffic_rate': bytes_rate,
                    'raw_packet_count': processed_count,
                    'timestamp': current_time
                },
                'anomalies': pd.DataFrame(),
                'features': pd.DataFrame(),
                'threat_analysis': {
                    'detected_ddos': False,
                    'message': "No threats detected",
                    'risk_level': "None"
                }
            })
                
        except Exception as e:
            print(f"Traffic capture error: {e}")
            import traceback
            traceback.print_exc()
            
        # Wait before capturing again
        time.sleep(2)  # Further reduce wait time for smoother charts

def anomaly_detection_thread():
    """Thread for anomaly detection"""
    global traffic_data, anomalies, ddos_features, threat_analysis
    
    # Wait for initial data collection
    time.sleep(15)
    
    while True:
        try:
            if len(traffic_data) > 10:  # Ensure sufficient data
                print("Extracting DDoS features...")
                
                # Extract DDoS features from the most recent data
                # Use only data from the last 5 minutes
                current_time = time.time()
                recent_data = [p for p in traffic_data if p['timestamp'] > current_time - 300]
                
                features = extract_ddos_features(recent_data)
                if not features.empty:
                    ddos_features = features  # Update global features
                    print(f"Extracted features from {len(features)} flows")
                    
                    # Train or update model
                    model, feature_cols = train_isolation_forest(features)
                    
                    # Detect anomalies
                    if model is not None:
                        results = detect_anomalies(model, features, feature_cols)
                        
                        # Analyze for DDoS threats
                        threat_analysis = analyze_ddos_threats(results)
                        print(f"DDoS analysis: {threat_analysis['message']}")
                        
                        # Store anomalies
                        new_anomalies = results[results['is_anomaly'] == -1].copy()
                        if not new_anomalies.empty:
                            # Add timestamp for anomalies
                            new_anomalies['detection_time'] = time.time()
                            anomalies.extend(new_anomalies.to_dict('records'))
                            print(f"Detected {len(new_anomalies)} anomalies")
                            
                            # Limit anomalies list size
                            if len(anomalies) > 1000:
                                anomalies = anomalies[-1000:]
                        
                        # Put analysis results into queue
                        current_time = time.time()
                        data_queue.put({
                            'traffic_stats': {
                                'packet_count': len(traffic_data),
                                'protocol_stats': protocol_distribution,
                                'traffic_rate': 0,  # This value will be updated in data_collection_thread
                                'raw_packet_count': 0,
                                'timestamp': current_time
                            },
                            'anomalies': new_anomalies if not new_anomalies.empty else pd.DataFrame(),
                            'features': features,
                            'threat_analysis': threat_analysis
                        })
            
        except Exception as e:
            print(f"Anomaly detection error: {e}")
            import traceback
            traceback.print_exc()
        
        time.sleep(30)  # Run every 30 seconds

def import_data_thread():
    """Thread for importing and processing data from CSV"""
    global traffic_data, anomalies, ddos_features, threat_analysis
    
    try:
        # Read CSV file
        df = pd.read_csv('c:\\Users\\zla77\\Desktop\\5700\\project\\ddos_data.csv')
        print("CSV data imported successfully.")
        
        # Process data
        for index, row in df.iterrows():
            # Simulate processing each row of data
            processed_packet = {
                'timestamp': time.time(),
                'src_ip': row['src_ip'],
                'dst_ip': row['dst_ip'],
                'protocol': row['protocol'],
                'size': row['Flow Bytes/s'],  # Assume using Flow Bytes/s as packet size
                'features': row.to_dict()
            }
            traffic_data.append(processed_packet)
            
            # Extract features and detect anomalies
            features = extract_ddos_features([processed_packet])
            if not features.empty:
                model, feature_cols = train_isolation_forest(features)
                results = detect_anomalies(model, features, feature_cols)
                threat_analysis = analyze_ddos_threats(results)
                
                # Store anomalies
                new_anomalies = results[results['is_anomaly'] == -1].copy()
                if not new_anomalies.empty:
                    new_anomalies['detection_time'] = time.time()
                    anomalies.extend(new_anomalies.to_dict('records'))
                    
                    # Limit anomalies list size
                    if len(anomalies) > 1000:
                        anomalies = anomalies[-1000:]
                
                # Put analysis results into queue
                data_queue.put({
                    'traffic_stats': {
                        'packet_count': len(traffic_data),
                        'protocol_stats': protocol_distribution,
                        'traffic_rate': 0,
                        'raw_packet_count': 0,
                        'timestamp': time.time()
                    },
                    'anomalies': new_anomalies if not new_anomalies.empty else pd.DataFrame(),
                    'features': features,
                    'threat_analysis': threat_analysis
                })
                
    except Exception as e:
        print(f"Error importing data from CSV: {e}")
        import traceback
        traceback.print_exc()

def main():
    print("Starting AI-Powered Network Traffic Analyzer...")
    
    # Create a queue specifically for chart data
    chart_data_queue = queue.Queue()
    
    # Start data collection thread
    print("Initializing data collection...")
    data_thread = threading.Thread(target=data_collection_thread)
    data_thread.daemon = True
    data_thread.start()
    
    # Start anomaly detection thread
    print("Initializing anomaly detection...")
    anomaly_thread = threading.Thread(target=anomaly_detection_thread)
    anomaly_thread.daemon = True
    anomaly_thread.start()
    
    # Start import data thread
    print("Initializing data import from CSV...")
    import_thread = threading.Thread(target=import_data_thread)
    import_thread.daemon = True
    import_thread.start()
    
    # Start a thread specifically for collecting chart data
    def chart_data_collector():
        current_time = time.time()  # Fix issue with current_time being undefined
        chart_data = []
        while True:
            try:
                # Extract the latest data point from the time series data
                if traffic_time_series:
                    latest = traffic_time_series[-1]
                    current_time = latest['timestamp']  # Update current_time
                    chart_data.append({
                        'time': latest['timestamp'],
                        'bytes_rate': latest['bytes_rate'],
                        'packets': latest['packet_count']
                    })
                    
                    # Limit data size
                    if len(chart_data) > 100:
                        chart_data = chart_data[-100:]
                    
                    # Put data into chart queue
                    # No longer use a separate queue, use the global data_queue
                    data_queue.put({
                        'traffic_stats': {
                            'packet_count': len(traffic_data),
                            'protocol_stats': protocol_distribution,
                            'traffic_rate': latest['bytes_rate'],
                            'raw_packet_count': latest['packet_count'],
                            'timestamp': current_time
                        },
                        'anomalies': pd.DataFrame(),
                        'features': pd.DataFrame(),
                        'threat_analysis': threat_analysis
                    })
                else:
                    current_time = time.time()  # Update current_time if no data
            except Exception as e:
                print(f"Chart data collector error: {e}")
                import traceback
                traceback.print_exc()
            
            time.sleep(1)
    
    chart_thread = threading.Thread(target=chart_data_collector)
    chart_thread.daemon = True
    chart_thread.start()
    
    # Launch dashboard with access to global data
    print("Launching dashboard...")
    create_dashboard(use_external_data=True)

if __name__ == "__main__":
    main()