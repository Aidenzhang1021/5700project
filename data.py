import random
import time
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def generate_mock_traffic_data(num_records=1000, include_anomalies=True, anomaly_ratio=0.05):
    """
    生成模拟网络流量数据
    
    参数:
    num_records -- 要生成的记录数量
    include_anomalies -- 是否包含异常流量
    anomaly_ratio -- 异常流量占总流量的比例
    
    返回:
    包含模拟网络流量数据的DataFrame
    """
    # 常见协议和端口
    protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SMTP"]
    protocol_weights = [0.45, 0.25, 0.05, 0.15, 0.05, 0.03, 0.02]
    
    common_ports = {
        "HTTP": 80,
        "HTTPS": 443,
        "DNS": 53,
        "SMTP": 25,
        "TCP": [21, 22, 23, 3389],
        "UDP": [53, 123, 161, 5353]
    }
    
    # 生成基本IP地址
    internal_ips = [f"192.168.1.{i}" for i in range(1, 30)]
    external_ips = [f"203.0.113.{i}" for i in range(1, 50)] + [f"8.8.{i}.{j}" for i in range(4, 10) for j in range(1, 10)]
    
    # 开始时间（24小时前）
    start_time = time.time() - 86400
    
    data = []
    anomaly_count = 0
    max_anomalies = int(num_records * anomaly_ratio)
    
    for i in range(num_records):
        # 决定是否生成异常数据
        is_anomaly = include_anomalies and anomaly_count < max_anomalies and random.random() < anomaly_ratio
        
        if is_anomaly:
            anomaly_count += 1
            record = generate_anomalous_record(start_time, i, internal_ips, external_ips)
        else:
            record = generate_normal_record(start_time, i, protocols, protocol_weights, common_ports, internal_ips, external_ips)
        
        data.append(record)
    
    # 转换为DataFrame并按时间排序
    df = pd.DataFrame(data)
    df = df.sort_values('timestamp')
    
    print(f"生成了{len(df)}条记录，包含{anomaly_count}条异常")
    return df

def generate_normal_record(start_time, index, protocols, protocol_weights, common_ports, internal_ips, external_ips):
    """生成正常网络流量记录"""
    # 基本时间戳（略微递增，加一些随机性）
    timestamp = start_time + index * 2 + random.random() * 4
    
    # 随机选择协议
    protocol = random.choices(protocols, weights=protocol_weights)[0]
    
    # 源IP和目标IP
    if random.random() < 0.6:  # 60%的流量是从内部到外部
        src_ip = random.choice(internal_ips)
        dst_ip = random.choice(external_ips)
    else:  # 40%的流量是从外部到内部
        src_ip = random.choice(external_ips)
        dst_ip = random.choice(internal_ips)
    
    # 端口
    if protocol in common_ports:
        if isinstance(common_ports[protocol], list):
            dst_port = random.choice(common_ports[protocol])
        else:
            dst_port = common_ports[protocol]
    else:
        dst_port = random.randint(1024, 65535)
    
    src_port = random.randint(49152, 65535)  # 临时端口范围
    
    # 数据包大小（正常分布）
    size = max(40, int(random.normalvariate(500, 200)))
    
    # 流持续时间（大部分很短）
    duration = random.expovariate(1.0) * 2
    
    # 生成记录
    return {
        'timestamp': timestamp,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'src_port': src_port,
        'dst_port': dst_port,
        'size': size,
        'duration': duration,
        'packets': random.randint(1, 10),
        'bytes': size * random.randint(1, 10)
    }

def generate_anomalous_record(start_time, index, internal_ips, external_ips):
    """生成异常网络流量记录"""
    timestamp = start_time + index * 2 + random.random() * 4
    
    anomaly_type = random.choice([
        "port_scan", 
        "ddos", 
        "data_exfiltration", 
        "unusual_protocol", 
        "unusual_port"
    ])
    
    if anomaly_type == "port_scan":
        # 端口扫描：单一源IP访问多个端口
        src_ip = random.choice(external_ips)
        dst_ip = random.choice(internal_ips)
        protocol = "TCP"
        src_port = random.randint(49152, 65535)
        dst_port = random.randint(1, 1024)  # 低端口通常是服务端口
        size = random.randint(40, 100)  # 扫描数据包通常较小
        duration = random.random() * 0.1  # 短暂连接
        
    elif anomaly_type == "ddos":
        # DDoS：同一目标，多源IP
        src_ip = f"103.{random.randint(1, 200)}.{random.randint(1, 200)}.{random.randint(1, 200)}"
        dst_ip = random.choice(internal_ips)
        protocol = random.choice(["TCP", "UDP", "ICMP"])
        src_port = random.randint(1, 65535)
        dst_port = random.choice([80, 443, 53, 22])
        size = random.randint(60, 1500)
        duration = random.random() * 0.5
        
    elif anomaly_type == "data_exfiltration":
        # 数据泄露：内部到外部的大量数据
        src_ip = random.choice(internal_ips)
        dst_ip = f"185.{random.randint(1, 200)}.{random.randint(1, 200)}.{random.randint(1, 200)}"
        protocol = random.choice(["TCP", "HTTP", "HTTPS"])
        src_port = random.randint(49152, 65535)
        dst_port = random.choice([80, 443, 8080, 21])
        size = random.randint(1500, 8000)  # 异常大的数据包
        duration = random.uniform(5, 15)  # 较长的连接
        
    elif anomaly_type == "unusual_protocol":
        # 不常见的协议
        src_ip = random.choice(external_ips)
        dst_ip = random.choice(internal_ips)
        protocol = random.choice(["ICMP", "GRE", "ESP", "IGMP"])
        src_port = 0  # 某些协议没有端口
        dst_port = 0
        size = random.randint(100, 1000)
        duration = random.random() * 3
        
    else:  # unusual_port
        # 不寻常的端口
        src_ip = random.choice(external_ips)
        dst_ip = random.choice(internal_ips)
        protocol = "TCP"
        src_port = random.randint(49152, 65535)
        dst_port = random.choice([4444, 5555, 6666, 31337])  # 可疑端口
        size = random.randint(200, 1000)
        duration = random.uniform(1, 10)
    
    return {
        'timestamp': timestamp,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'src_port': src_port,
        'dst_port': dst_port,
        'size': size,
        'duration': duration,
        'packets': random.randint(1, 20),
        'bytes': size * random.randint(1, 30),
        'anomaly_type': anomaly_type
    }

# 使用示例
if __name__ == "__main__":
    # 生成1000条记录，包含5%的异常
    mock_data = generate_mock_traffic_data(1000, include_anomalies=True, anomaly_ratio=0.05)
    
    # 显示数据概览
    print("\n数据概览:")
    print(mock_data.head())
    
    # 显示不同协议的分布
    print("\n协议分布:")
    print(mock_data['protocol'].value_counts())
    
    # 保存到CSV文件
    # 保存到特定位置
    mock_data.to_csv('C:/Users/zla77/Desktop/5700/project/mock_network_traffic.csv', index=False)
    print("\n数据已保存到 mock_network_traffic.csv")