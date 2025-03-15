import threading
import time
import pandas as pd
import numpy as np
from data_layer import capture_traffic, packet_callback, extract_ddos_features
from ai_layer import train_isolation_forest, detect_anomalies, analyze_ddos_threats
from app_layer import create_dashboard

# Global data store
traffic_data = []
anomalies = []
ddos_features = pd.DataFrame()
threat_analysis = {}

def data_collection_thread():
    """Thread for continuous data collection"""
    global traffic_data
    
    while True:
        try:
            # Capture real-time traffic
            print("Starting to capture network traffic...")
            new_packets = capture_traffic(count=50)  # Using defined interface
            print(f"Captured {len(new_packets)} packets")
            
            # Process and store data
            for packet in new_packets:
                processed_packet = packet_callback(packet)
                if processed_packet:
                    traffic_data.append(processed_packet)
            
            print(f"Currently processed {len(traffic_data)} packets")
            
            # Limit the size of traffic_data to control memory usage
            max_packets = 10000
            if len(traffic_data) > max_packets:
                traffic_data = traffic_data[-max_packets:]
                
        except Exception as e:
            print(f"Traffic capture error: {e}")
            
        # Wait before capturing again
        time.sleep(10)  # Reduced wait time for more frequent updates

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
            
        except Exception as e:
            print(f"Anomaly detection error: {e}")
            import traceback
            traceback.print_exc()
        
        time.sleep(30)  # Run every 30 seconds

def main():
    print("Starting AI-Powered Network Traffic Analyzer...")
    
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
    
    # Launch dashboard with access to global data
    print("Launching dashboard...")
    create_dashboard()

if __name__ == "__main__":
    main()