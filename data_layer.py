# Real-time network traffic capture using Scapy
from scapy.all import sniff, IP, TCP, UDP, ICMP
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
        
        # 添加TCP标志信息（对DDoS检测有用）
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
        interface = r"\Device\NPF_{27A17632-B031-40F1-A304-7C2B1A53D2BE}"
        packets = sniff(iface=interface, prn=packet_callback, count=count)
        return packets
    except Exception as e:
        print(f"Error in traffic capture: {e}")
        return []

def extract_ddos_features(packets, time_window=60):
    """从实时捕获的数据包中提取DDoS检测的关键特征"""
    if not packets or len(packets) < 2:
        return pd.DataFrame()
        
    # 将数据包列表转换为DataFrame
    df = pd.DataFrame(packets)
    
    # 对数据按源IP、目标IP、协议分组
    df['flow_id'] = df.apply(lambda x: f"{x['src_ip']}_{x['dst_ip']}_{x['protocol']}", axis=1)
    
    # 计算每个流的时间窗口和持续时间
    flow_stats = {}
    
    for flow, group in df.groupby('flow_id'):
        # 1. 计算流量率特征
        duration = group['timestamp'].max() - group['timestamp'].min()
        if duration < 0.001:  # 避免除以零
            duration = 0.001
            
        total_bytes = group['size'].sum()
        packet_count = len(group)
        
        # 2. 计算数据包大小特征
        packet_size_mean = group['size'].mean()
        
        # 3. 计算IAT特征
        sorted_group = group.sort_values('timestamp')
        iat_values = sorted_group['timestamp'].diff().dropna().values
        flow_iat_mean = np.mean(iat_values) if len(iat_values) > 0 else 0
        
        # 提取源IP和目标IP，用于后续分析
        src_ip = group['src_ip'].iloc[0]
        dst_ip = group['dst_ip'].iloc[0]
        protocol = group['protocol'].iloc[0]
        
        # 计算TCP SYN标志比例（对SYN洪水攻击检测有用）
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
    
    # 转换为DataFrame
    result = pd.DataFrame.from_dict(flow_stats, orient='index').reset_index()
    result.rename(columns={'index': 'flow_id'}, inplace=True)
    
    return result

def main():
    # 测试数据捕获和特征提取功能
    print("Testing data layer functionality...")
    
    try:
        # 捕获网络流量
        print("Capturing packets...")
        packets = capture_traffic(count=30)
        
        # 处理数据包
        processed_packets = []
        for packet in packets:
            processed_packet = packet_callback(packet)
            if processed_packet:
                processed_packets.append(processed_packet)
        
        print(f"Successfully captured {len(processed_packets)} packets")
        
        # 显示样例数据
        if processed_packets:
            print("\nSample packet data:")
            for key, value in processed_packets[0].items():
                print(f"  {key}: {value}")
        
        # 提取特征
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