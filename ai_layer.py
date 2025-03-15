from sklearn.ensemble import IsolationForest
import joblib
import pandas as pd
import numpy as np

def train_isolation_forest(features_df):
    """
    Train an Isolation Forest model using real-time traffic features
    
    Parameters:
    features_df - DataFrame containing key DDoS features extracted from the data layer
    """
    # Ensure input data is valid
    if features_df.empty:
        print("Error: Empty features dataframe, cannot train model")
        return None
    
    # Select numerical features for training
    # Exclude non-numerical columns and non-feature columns
    exclude_cols = ['flow_id', 'src_ip', 'dst_ip', 'protocol', 'is_anomaly', 'anomaly_score']
    feature_cols = [col for col in features_df.columns if col not in exclude_cols and features_df[col].dtype in ['int64', 'float64']]
    
    if not feature_cols:
        print("Error: No numeric feature columns found")
        return None
    
    X = features_df[feature_cols]
    
    # Initialize and train the Isolation Forest model
    model = IsolationForest(
        n_estimators=100,
        max_samples='auto',
        contamination=0.05,  # Expected anomaly ratio
        random_state=42
    )
    
    model.fit(X)
    
    # Save the trained model
    joblib.dump(model, 'isolation_forest_model.pkl')
    
    return model, feature_cols

def detect_anomalies(model, features_df, feature_cols=None):
    """
    Detect anomalous traffic using the trained model
    
    Parameters:
    model - Trained Isolation Forest model
    features_df - DataFrame containing features to be detected
    feature_cols - List of feature column names to use for prediction
    """
    if features_df.empty:
        print("Error: Empty features dataframe, cannot detect anomalies")
        return features_df
    
    # If feature columns are not provided, automatically select numerical columns
    if feature_cols is None:
        exclude_cols = ['flow_id', 'src_ip', 'dst_ip', 'protocol', 'is_anomaly', 'anomaly_score']
        feature_cols = [col for col in features_df.columns if col not in exclude_cols and features_df[col].dtype in ['int64', 'float64']]
    
    # Ensure all required feature columns exist
    missing_cols = [col for col in feature_cols if col not in features_df.columns]
    if missing_cols:
        print(f"Warning: Missing feature columns: {missing_cols}")
        feature_cols = [col for col in feature_cols if col in features_df.columns]
    
    if not feature_cols:
        print("Error: No feature columns available for prediction")
        return features_df
    
    # Extract feature data
    X = features_df[feature_cols]
    
    # Predict anomalies (-1 indicates anomaly, 1 indicates normal)
    predictions = model.predict(X)
    
    # Calculate anomaly scores
    scores = model.decision_function(X)
    
    # Add results to the original data
    features_df['is_anomaly'] = predictions
    features_df['anomaly_score'] = scores
    
    # Calculate risk score (between 0-1, 1 indicates highest risk)
    min_score = scores.min()
    max_score = scores.max()
    
    # Avoid division by zero if all scores are the same
    if max_score == min_score:
        features_df['risk_score'] = 0.5 if min_score < 0 else 0.0
    else:
        # Convert anomaly scores to risk scores between 0-1 (more negative score indicates higher risk)
        features_df['risk_score'] = (max_score - scores) / (max_score - min_score)
    
    return features_df

def analyze_ddos_threats(anomalies_df):
    """
    Analyze detected anomalies to determine if DDoS threats exist
    
    Parameters:
    anomalies_df - DataFrame with anomaly flags
    
    Returns:
    Threat analysis results
    """
    if anomalies_df.empty:
        return {
            'detected_ddos': False,
            'message': "No data available for analysis",
            'risk_level': "None"
        }
    
    # Get flows detected as anomalies
    anomalies = anomalies_df[anomalies_df['is_anomaly'] == -1]
    
    if anomalies.empty:
        return {
            'detected_ddos': False,
            'message': "No anomalies detected",
            'risk_level': "None"
        }
    
    # Analyze anomaly features to determine if they match DDoS characteristics
    ddos_indicators = []
    
    # 1. Check for high flow rates
    if 'Flow Packets/s' in anomalies.columns:
        high_packet_rate = anomalies['Flow Packets/s'] > anomalies_df['Flow Packets/s'].quantile(0.95)
        if high_packet_rate.any():
            ddos_indicators.append("High packet rate detected")
    
    # 2. Check for small IAT (Interarrival Time)
    if 'Flow IAT Mean' in anomalies.columns:
        small_iat = anomalies['Flow IAT Mean'] < anomalies_df['Flow IAT Mean'].quantile(0.05)
        if small_iat.any():
            ddos_indicators.append("Small interarrival time detected")
    
    # 3. Check for SYN flood characteristics
    if 'SYN Ratio' in anomalies.columns:
        high_syn_ratio = anomalies['SYN Ratio'] > 0.8
        if high_syn_ratio.any():
            ddos_indicators.append("High SYN ratio detected")
    
    # Determine risk level
    risk_score = anomalies['risk_score'].max() if 'risk_score' in anomalies.columns else 0.5
    
    if len(ddos_indicators) >= 2 or risk_score > 0.8:
        risk_level = "High"
    elif len(ddos_indicators) == 1 or risk_score > 0.5:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    # Determine if DDoS threats exist
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
        # Test AI layer functionality
        print("Testing AI Layer functionality with synthetic data...")
        
        # Create simulated DDoS feature data
        np.random.seed(42)
        
        # Normal traffic features
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
                'SYN Ratio': np.random.beta(1, 10)  # Low SYN ratio
            })
        
        # Anomalous traffic features (DDoS pattern)
        anomaly_data = []
        for i in range(5):
            anomaly_data.append({
                'flow_id': f"anomaly_flow_{i}",
                'src_ip': f"172.16.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'dst_ip': "10.0.0.1",  # Same target
                'protocol': 'TCP',
                'Flow Bytes/s': np.random.normal(50000, 10000),  # High traffic
                'Flow Packets/s': np.random.normal(500, 100),    # High packet rate
                'Packet Length Mean': np.random.normal(100, 20),  # Small packets
                'Flow IAT Mean': np.random.normal(0.001, 0.0002),  # Small IAT
                'SYN Ratio': np.random.beta(10, 1)  # High SYN ratio
            })
        
        # Merge data
        all_data = normal_data + anomaly_data
        df = pd.DataFrame(all_data)
        
        print(f"Created synthetic dataset with {len(df)} flows")
        
        # Train model
        print("\nTraining isolation forest model...")
        model, feature_cols = train_isolation_forest(df)
        
        if model is not None:
            # Detect anomalies
            print("\nDetecting anomalies...")
            results = detect_anomalies(model, df, feature_cols)
            
            print(f"Total samples: {len(results)}")
            print(f"Detected anomalies: {sum(results['is_anomaly'] == -1)}")
            
            # Display detected anomalies
            detected_anomalies = results[results['is_anomaly'] == -1]
            if not detected_anomalies.empty:
                print("\nDetected anomalies:")
                display_cols = ['flow_id', 'src_ip', 'dst_ip', 'Flow Packets/s', 'Flow IAT Mean', 'risk_score']
                display_cols = [col for col in display_cols if col in detected_anomalies.columns]
                print(detected_anomalies[display_cols].head())
                
                # Analyze DDoS threats
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