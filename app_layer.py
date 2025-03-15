import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import time
from datetime import datetime, timedelta
import threading
import queue

# 导入其他层的功能
from data_layer import capture_traffic, packet_callback, extract_ddos_features
from ai_layer import train_isolation_forest, detect_anomalies, analyze_ddos_threats

# 创建全局变量用于在线程间共享数据
traffic_data = []
latest_features = pd.DataFrame()
latest_anomalies = pd.DataFrame()
threat_analysis = {"detected_ddos": False, "message": "No data analyzed yet", "risk_level": "None"}
data_queue = queue.Queue()
stop_thread = threading.Event()

def monitor_traffic_thread():
    """后台线程，持续捕获和分析网络流量"""
    global traffic_data, latest_features, latest_anomalies, threat_analysis
    
    # 初始化模型
    model = None
    feature_cols = None
    
    while not stop_thread.is_set():
        try:
            # 捕获一批数据包
            packets = capture_traffic(count=20)  # 每次捕获20个包
            
            # 处理数据包
            new_packets = []
            for packet in packets:
                processed_packet = packet_callback(packet)
                if processed_packet:
                    new_packets.append(processed_packet)
            
            # 添加到全局数据
            if new_packets:
                traffic_data.extend(new_packets)
                
                # 保持数据集大小可控（保留最近10000个数据包）
                if len(traffic_data) > 10000:
                    traffic_data = traffic_data[-10000:]
                
                # 提取特征
                if len(traffic_data) > 10:  # 确保有足够数据
                    # 仅处理最近的数据（滑动窗口）
                    window_size = 300  # 5分钟内的数据
                    current_time = time.time()
                    window_data = [p for p in traffic_data if p['timestamp'] > current_time - window_size]
                    
                    features = extract_ddos_features(window_data)
                    if not features.empty:
                        latest_features = features
                        
                        # 如果模型为空或数据量增长显著，重新训练模型
                        if model is None or len(features) > 100 and len(features) % 100 == 0:
                            model, feature_cols = train_isolation_forest(features)
                        
                        # 检测异常
                        if model is not None:
                            results = detect_anomalies(model, features, feature_cols)
                            latest_anomalies = results[results['is_anomaly'] == -1].copy()
                            
                            # 分析DDoS威胁
                            threat_analysis = analyze_ddos_threats(results)
                            
                            # 将数据放入队列供UI使用
                            data_queue.put({
                                'features': features,
                                'anomalies': latest_anomalies,
                                'threat_analysis': threat_analysis,
                                'traffic_stats': {
                                    'packet_count': len(window_data),
                                    'protocol_stats': pd.Series([p['protocol'] for p in window_data]).value_counts().to_dict(),
                                    'traffic_rate': features['Flow Bytes/s'].mean() if 'Flow Bytes/s' in features.columns else 0,
                                    'raw_packet_count': len(new_packets)  # 添加原始数据包计数
                                }
                            })
            
            time.sleep(2)  # 控制捕获频率
            
        except Exception as e:
            print(f"Error in monitoring thread: {e}")
            time.sleep(5)  # 出错后等待时间长一些

def create_dashboard():
    st.set_page_config(page_title="AI-Powered Network Traffic Analyzer", layout="wide")
    
    st.title("AI-Powered Network Traffic Analyzer")
    
    # 初始化session state
    if 'traffic_chart_data' not in st.session_state:
        st.session_state.traffic_chart_data = pd.DataFrame({'packets': [0]})
        st.session_state.last_update_time = time.time()
    
    # Sidebar configuration
    st.sidebar.header("Control Panel")
    
    monitor_active = st.sidebar.checkbox("Start Real-time Monitoring", value=True)
    
    protocol_filter = st.sidebar.multiselect(
        "Select Protocols to Filter",
        ["TCP", "UDP", "ICMP", "HTTP", "All"],
        default=["All"]
    )
    
    alert_threshold = st.sidebar.slider("Alert Sensitivity", 0.0, 1.0, 0.7)
    
    # Start or stop monitoring thread based on checkbox
    if monitor_active:
        if stop_thread.is_set():
            stop_thread.clear()
            monitoring_thread = threading.Thread(target=monitor_traffic_thread)
            monitoring_thread.daemon = True
            monitoring_thread.start()
            st.sidebar.success("Monitoring started")
    else:
        stop_thread.set()
        st.sidebar.warning("Monitoring stopped")
    
    # Main interface layout
    col1, col2 = st.columns(2)
    
    # Real-time traffic monitoring
    with col1:
        st.subheader("Real-time Traffic Monitoring")
        
        # 使用session_state存储的数据创建图表
        traffic_chart = st.line_chart(st.session_state.traffic_chart_data)
        
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
    update_interval = 1  # seconds - 减少更新间隔以获得更平滑的图表
    
    # 为折线图初始化数据缓冲区
    if 'packet_rate_buffer' not in st.session_state:
        st.session_state.packet_rate_buffer = []
    
    protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0, "Other": 0}
    last_packet_count = 0
    
    while monitor_active:
        # 更新图表的计时器
        current_time = time.time()
        time_diff = current_time - st.session_state.last_update_time
        
        # 检查新数据
        new_data_available = False
        
        try:
            while not data_queue.empty():
                data = data_queue.get(block=False)
                new_data_available = True
                
                # 更新指标
                packet_counter.metric("Packets", data['traffic_stats']['packet_count'], 
                                    delta=data['traffic_stats']['packet_count'] - last_packet_count if last_packet_count > 0 else None)
                last_packet_count = data['traffic_stats']['packet_count']
                
                bytes_rate.metric("Traffic Rate", f"{data['traffic_stats']['traffic_rate']:.2f} B/s")
                
                anomaly_count = len(data['anomalies'])
                anomaly_counter.metric("Anomalies", anomaly_count)
                
                # 更新协议分布
                for protocol, count in data['traffic_stats']['protocol_stats'].items():
                    protocol_counts[protocol] = protocol_counts.get(protocol, 0) + count
                
                # 只保留有值的协议
                filtered_protocols = {k: v for k, v in protocol_counts.items() if v > 0}
                
                if filtered_protocols:
                    fig, ax = plt.subplots()
                    wedges, texts, autotexts = ax.pie(
                        filtered_protocols.values(), 
                        labels=filtered_protocols.keys(),
                        autopct='%1.1f%%'
                    )
                    protocol_chart_placeholder.pyplot(fig)
                
                # 更新流量图表数据 - 添加数据包数量
                if 'raw_packet_count' in data['traffic_stats']:
                # 为了测试添加一些随机波动
                    packet_count = data['traffic_stats']['raw_packet_count']
                # 如果数据都是0，添加一些随机值用于测试
                    if packet_count == 0:
                        packet_count = np.random.randint(1, 10)  # 随机生成1-10之间的值
                
                # 添加到session状态的数据
                    new_point = {'packets': packet_count}
                    new_df = pd.DataFrame([new_point])
                
                # 更新图表
                    traffic_chart.add_rows(new_df)
                
                # 更新警报
                if 'anomalies' in data and not data['anomalies'].empty and anomaly_count > 0:
                    # 基于阈值过滤警报
                    high_risk_anomalies = data['anomalies'][data['anomalies']['risk_score'] >= alert_threshold]
                    
                    with alerts_container:
                        for _, anomaly in high_risk_anomalies.iterrows():
                            if 'risk_score' in anomaly and 'src_ip' in anomaly and 'dst_ip' in anomaly:
                                st.warning(f"Suspicious traffic detected: {anomaly['src_ip']} → {anomaly['dst_ip']} - Risk score: {anomaly['risk_score']:.2f}")
                
                # 更新威胁分析
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
                
                # 更新流量统计
                if 'features' in data and not data['features'].empty:
                    cols_to_show = ['src_ip', 'dst_ip', 'protocol', 'Flow Packets/s', 'Flow Bytes/s', 'Flow IAT Mean']
                    available_cols = [col for col in cols_to_show if col in data['features'].columns]
                    
                    if available_cols:
                        flow_stats_container.dataframe(data['features'][available_cols].head(10))
                
                # 更新异常详情
                if 'anomalies' in data and not data['anomalies'].empty:
                    cols_to_show = ['src_ip', 'dst_ip', 'protocol', 'Flow Packets/s', 'risk_score']
                    available_cols = [col for col in cols_to_show if col in data['anomalies'].columns]
                    
                    if available_cols:
                        anomaly_container.dataframe(
                            data['anomalies'][available_cols].sort_values('risk_score', ascending=False).head(10)
                        )
                else:
                    anomaly_container.info("No anomalies detected")
                
                # 更新协议分析
                protocol_summary = pd.Series(data['traffic_stats']['protocol_stats']).reset_index()
                protocol_summary.columns = ['Protocol', 'Count']
                if not protocol_summary.empty:
                    protocol_details.bar_chart(protocol_summary.set_index('Protocol'))
            
            # 如果没有新数据，但已经过了一定时间，也添加数据点以保持图表活动
            if not new_data_available and time_diff > 3:
                # 添加零值数据点
                new_point = {'packets': 0}
                new_df = pd.DataFrame([new_point])
                st.session_state.traffic_chart_data = pd.concat([st.session_state.traffic_chart_data, new_df], ignore_index=True)
                
                # 保持数据大小可控
                if len(st.session_state.traffic_chart_data) > 100:
                    st.session_state.traffic_chart_data = st.session_state.traffic_chart_data.iloc[-100:]
                
                # 更新图表
                traffic_chart.add_rows(new_df)
                st.session_state.last_update_time = current_time
        
        except Exception as e:
            st.error(f"Error updating dashboard: {e}")
            import traceback
            traceback.print_exc()
        
        time.sleep(update_interval)
        
        # 检查复选框是否被取消选中
        if not monitor_active:
            break

if __name__ == "__main__":
    create_dashboard()