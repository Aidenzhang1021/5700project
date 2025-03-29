# Real-time network traffic capture using Scapy
from scapy.all import get_working_if, sniff, IP, TCP, UDP, ICMP, conf, get_working_ifaces
import pandas as pd
import numpy as np
import time

def packet_callback(packet):
    if IP in packet:
        timestamp = time.time()
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "Other"
        size = len(packet)
        
        # Add TCP flag information (useful for DDoS detection)
        syn_flag = 0
        if TCP in packet:
            syn_flag = 1 if packet[TCP].flags & 0x02 else 0
        
        # Store captured data
        packet_data = {
            'timestamp': timestamp,
            'src_ip': ip_src,
            'dst_ip': ip_dst,
            'protocol': protocol,
            'size': size,
            'syn_flag': syn_flag
        }
        
        return packet_data
    return None

# Start traffic capture
def capture_traffic(interface=None, count=100):
    try:
        if interface is None:
            interface = get_working_if()
            print(f"Automatically selected interface: {interface}")

        packets = sniff(iface=interface, prn=packet_callback, count=count)
        return packets
    except Exception as e:
        print(f"Error in traffic capture: {e}")
        return []

def extract_ddos_features(packets, time_window=60):
    """Extract key features for DDoS detection from real-time captured packets"""
    if not packets or len(packets) < 2:
        return pd.DataFrame()
        
    # Convert packet list to DataFrame
    df = pd.DataFrame(packets)
    
    # Group data by source IP, destination IP, and protocol
    df['flow_id'] = df.apply(lambda x: f"{x['src_ip']}_{x['dst_ip']}_{x['protocol']}", axis=1)
    
    # Calculate time window and duration for each flow
    flow_stats = {}
    
    for flow, group in df.groupby('flow_id'):
        # 1. Calculate flow rate features
        duration = group['timestamp'].max() - group['timestamp'].min()
        if duration < 0.001:  # Avoid division by zero
            duration = 0.001
            
        total_bytes = group['size'].sum()
        packet_count = len(group)
        
        # 2. Calculate packet size features
        packet_size_mean = group['size'].mean()
        
        # 3. Calculate IAT features
        sorted_group = group.sort_values('timestamp')
        iat_values = sorted_group['timestamp'].diff().dropna().values
        flow_iat_mean = np.mean(iat_values) if len(iat_values) > 0 else 0
        
        # Extract source IP and destination IP for subsequent analysis
        src_ip = group['src_ip'].iloc[0]
        dst_ip = group['dst_ip'].iloc[0]
        protocol = group['protocol'].iloc[0]
        
        # Calculate TCP SYN flag ratio (useful for SYN flood attack detection)
        syn_ratio = 0
        if 'syn_flag' in group.columns:
            syn_ratio = group['syn_flag'].sum() / packet_count if packet_count > 0 else 0
        
        flow_stats[flow] = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'Flow Bytes/s': total_bytes / duration,
            'Flow Packets/s': packet_count / duration,
            'Packet Length Mean': packet_size_mean,
            'Flow IAT Mean': flow_iat_mean,
            'Total Packets': packet_count,
            'SYN Ratio': syn_ratio
        }
    
    # Convert to DataFrame
    result = pd.DataFrame.from_dict(flow_stats, orient='index').reset_index()
    result.rename(columns={'index': 'flow_id'}, inplace=True)
    
    return result

def main():
    # Test data capture and feature extraction functionality
    print("Testing data layer functionality...")
    
    try:
        # Capture network traffic
        print("Capturing packets...")
        packets = capture_traffic(count=30)
        
        # Process packets
        processed_packets = []
        for packet in packets:
            processed_packet = packet_callback(packet)
            if processed_packet:
                processed_packets.append(processed_packet)
        
        print(f"Successfully captured {len(processed_packets)} packets")
        
        # Display sample data
        if processed_packets:
            print("\nSample packet data:")
            for key, value in processed_packets[0].items():
                print(f"  {key}: {value}")
        
        # Extract features
        if len(processed_packets) >= 2:
            print("\nExtracting DDoS features...")
            features = extract_ddos_features(processed_packets)
            print(f"Extracted {len(features)} flow features")
            
            if not features.empty:
                print("\nSample features:")
                print(features.head())
        else:
            print("Not enough packets captured to extract features")
            
    except Exception as e:
        print(f"Error in data layer test: {e}")

if __name__ == "__main__":
    main()