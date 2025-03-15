from sklearn.ensemble import IsolationForest
import joblib
import pandas as pd
import numpy as np

def train_isolation_forest(features_df):
    """
    使用实时流量特征训练隔离森林模型
    
    参数:
    features_df - 包含从数据层提取的DDoS关键特征的DataFrame
    """
    # 确保输入数据有效
    if features_df.empty:
        print("Error: Empty features dataframe, cannot train model")
        return None
    
    # 选择数值型特征用于训练
    # 排除非数值列和非特征列
    exclude_cols = ['flow_id', 'src_ip', 'dst_ip', 'protocol', 'is_anomaly', 'anomaly_score']
    feature_cols = [col for col in features_df.columns if col not in exclude_cols and features_df[col].dtype in ['int64', 'float64']]
    
    if not feature_cols:
        print("Error: No numeric feature columns found")
        return None
    
    X = features_df[feature_cols]
    
    # 初始化并训练隔离森林模型
    model = IsolationForest(
        n_estimators=100,
        max_samples='auto',
        contamination=0.05,  # 预期异常比例
        random_state=42
    )
    
    model.fit(X)
    
    # 保存训练好的模型
    joblib.dump(model, 'isolation_forest_model.pkl')
    
    return model, feature_cols

def detect_anomalies(model, features_df, feature_cols=None):
    """
    使用训练好的模型检测异常流量
    
    参数:
    model - 训练好的隔离森林模型
    features_df - 包含待检测特征的DataFrame
    feature_cols - 用于预测的特征列名列表
    """
    if features_df.empty:
        print("Error: Empty features dataframe, cannot detect anomalies")
        return features_df
    
    # 如果没有提供特征列，自动选择数值型列
    if feature_cols is None:
        exclude_cols = ['flow_id', 'src_ip', 'dst_ip', 'protocol', 'is_anomaly', 'anomaly_score']
        feature_cols = [col for col in features_df.columns if col not in exclude_cols and features_df[col].dtype in ['int64', 'float64']]
    
    # 确保所有需要的特征列都存在
    missing_cols = [col for col in feature_cols if col not in features_df.columns]
    if missing_cols:
        print(f"Warning: Missing feature columns: {missing_cols}")
        feature_cols = [col for col in feature_cols if col in features_df.columns]
    
    if not feature_cols:
        print("Error: No feature columns available for prediction")
        return features_df
    
    # 提取特征数据
    X = features_df[feature_cols]
    
    # 预测异常（-1表示异常，1表示正常）
    predictions = model.predict(X)
    
    # 计算异常分数
    scores = model.decision_function(X)
    
    # 添加结果到原始数据
    features_df['is_anomaly'] = predictions
    features_df['anomaly_score'] = scores
    
    # 计算风险评分（0-1之间，1表示最高风险）
    min_score = scores.min()
    max_score = scores.max()
    
    # 如果所有分数相同，避免除以零
    if max_score == min_score:
        features_df['risk_score'] = 0.5 if min_score < 0 else 0.0
    else:
        # 将异常分数转换为0-1之间的风险分数（分数越负表示风险越高）
        features_df['risk_score'] = (max_score - scores) / (max_score - min_score)
    
    return features_df

def analyze_ddos_threats(anomalies_df):
    """
    分析检测到的异常，判断是否存在DDoS威胁
    
    参数:
    anomalies_df - 包含异常标记的DataFrame
    
    返回:
    威胁分析结果
    """
    if anomalies_df.empty:
        return {
            'detected_ddos': False,
            'message': "No data available for analysis",
            'risk_level': "None"
        }
    
    # 获取检测为异常的流
    anomalies = anomalies_df[anomalies_df['is_anomaly'] == -1]
    
    if anomalies.empty:
        return {
            'detected_ddos': False,
            'message': "No anomalies detected",
            'risk_level': "None"
        }
    
    # 分析异常特征，确定是否符合DDoS特征
    ddos_indicators = []
    
    # 1. 检查是否有高流量率
    if 'Flow Packets/s' in anomalies.columns:
        high_packet_rate = anomalies['Flow Packets/s'] > anomalies_df['Flow Packets/s'].quantile(0.95)
        if high_packet_rate.any():
            ddos_indicators.append("High packet rate detected")
    
    # 2. 检查是否有小IAT（Interarrival Time）
    if 'Flow IAT Mean' in anomalies.columns:
        small_iat = anomalies['Flow IAT Mean'] < anomalies_df['Flow IAT Mean'].quantile(0.05)
        if small_iat.any():
            ddos_indicators.append("Small interarrival time detected")
    
    # 3. 检查是否有SYN洪水特征
    if 'SYN Ratio' in anomalies.columns:
        high_syn_ratio = anomalies['SYN Ratio'] > 0.8
        if high_syn_ratio.any():
            ddos_indicators.append("High SYN ratio detected")
    
    # 确定风险级别
    risk_score = anomalies['risk_score'].max() if 'risk_score' in anomalies.columns else 0.5
    
    if len(ddos_indicators) >= 2 or risk_score > 0.8:
        risk_level = "High"
    elif len(ddos_indicators) == 1 or risk_score > 0.5:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    # 判断是否存在DDoS威胁
    is_ddos = len(ddos_indicators) > 0
    
    return {
        'detected_ddos': is_ddos,
        'message': f"DDoS indicators: {', '.join(ddos_indicators)}" if is_ddos else "No clear DDoS pattern detected",
        'risk_level': risk_level,
        'anomaly_count': len(anomalies),
        'potential_attackers': anomalies['src_ip'].unique().tolist() if 'src_ip' in anomalies.columns else [],
        'targets': anomalies['dst_ip'].unique().tolist() if 'dst_ip' in anomalies.columns else []
    }

def main():
    try:
        # 测试AI层功能
        print("Testing AI Layer functionality with synthetic data...")
        
        # 创建模拟的DDoS特征数据
        np.random.seed(42)
        
        # 正常流量特征
        normal_data = []
        for i in range(95):
            normal_data.append({
                'flow_id': f"flow_{i}",
                'src_ip': f"192.168.1.{np.random.randint(1, 100)}",
                'dst_ip': f"10.0.0.{np.random.randint(1, 10)}",
                'protocol': np.random.choice(['TCP', 'UDP', 'HTTP']),
                'Flow Bytes/s': np.random.normal(5000, 1000),
                'Flow Packets/s': np.random.normal(50, 10),
                'Packet Length Mean': np.random.normal(800, 200),
                'Flow IAT Mean': np.random.normal(0.02, 0.005),
                'SYN Ratio': np.random.beta(1, 10)  # 低SYN比例
            })
        
        # 异常流量特征（DDoS模式）
        anomaly_data = []
        for i in range(5):
            anomaly_data.append({
                'flow_id': f"anomaly_flow_{i}",
                'src_ip': f"172.16.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'dst_ip': "10.0.0.1",  # 同一目标
                'protocol': 'TCP',
                'Flow Bytes/s': np.random.normal(50000, 10000),  # 高流量
                'Flow Packets/s': np.random.normal(500, 100),    # 高包率
                'Packet Length Mean': np.random.normal(100, 20),  # 小包
                'Flow IAT Mean': np.random.normal(0.001, 0.0002),  # 小IAT
                'SYN Ratio': np.random.beta(10, 1)  # 高SYN比例
            })
        
        # 合并数据
        all_data = normal_data + anomaly_data
        df = pd.DataFrame(all_data)
        
        print(f"Created synthetic dataset with {len(df)} flows")
        
        # 训练模型
        print("\nTraining isolation forest model...")
        model, feature_cols = train_isolation_forest(df)
        
        if model is not None:
            # 检测异常
            print("\nDetecting anomalies...")
            results = detect_anomalies(model, df, feature_cols)
            
            print(f"Total samples: {len(results)}")
            print(f"Detected anomalies: {sum(results['is_anomaly'] == -1)}")
            
            # 显示检测到的异常
            detected_anomalies = results[results['is_anomaly'] == -1]
            if not detected_anomalies.empty:
                print("\nDetected anomalies:")
                display_cols = ['flow_id', 'src_ip', 'dst_ip', 'Flow Packets/s', 'Flow IAT Mean', 'risk_score']
                display_cols = [col for col in display_cols if col in detected_anomalies.columns]
                print(detected_anomalies[display_cols].head())
                
                # 分析DDoS威胁
                print("\nAnalyzing potential DDoS threats...")
                threat_analysis = analyze_ddos_threats(results)
                print(f"DDoS detected: {threat_analysis['detected_ddos']}")
                print(f"Risk level: {threat_analysis['risk_level']}")
                print(f"Analysis: {threat_analysis['message']}")
                
                if threat_analysis['detected_ddos']:
                    print(f"Potential attackers: {', '.join(threat_analysis['potential_attackers'][:5])}")
                    print(f"Target systems: {', '.join(threat_analysis['targets'])}")
    
    except Exception as e:
        print(f"Error in AI layer test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()