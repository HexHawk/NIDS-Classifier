import pandas as pd
import numpy as np
import random
from typing import Dict

# Define the NSL-KDD features
FEATURES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]

# Set random seed for reproducibility
np.random.seed(42)
random.seed(42)

def generate_row(is_attack: bool = False) -> Dict:
    """
    Generate a single row of NSL-KDD data.
    
    Args:
        is_attack: If True, generate attack traffic data, otherwise benign
        
    Returns:
        Dictionary with NSL-KDD features
    """
    row = {}
    
    # Categorical features
    row['protocol_type'] = random.choice(['tcp', 'udp', 'icmp'])
    
    services = ['http', 'ftp_data', 'smtp', 'ssh', 'dns', 'ftp', 'telnet', 'pop_3']
    row['service'] = random.choice(services)
    
    flags = ['SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'S1', 'S2', 'S3']
    row['flag'] = random.choice(flags)
    
    # Numeric features with appropriate ranges
    row['duration'] = int(np.random.exponential(scale=300) if is_attack else np.random.exponential(scale=100))
    row['src_bytes'] = int(np.random.exponential(scale=10000) if is_attack else np.random.exponential(scale=2000))
    row['dst_bytes'] = int(np.random.exponential(scale=5000) if is_attack else np.random.exponential(scale=1000))
    
    # Binary features
    row['land'] = random.randint(0, 1) if is_attack and random.random() < 0.2 else 0
    row['wrong_fragment'] = random.randint(0, 1) if is_attack and random.random() < 0.3 else 0
    row['urgent'] = random.randint(0, 1) if is_attack and random.random() < 0.1 else 0
    
    # More attack indicators
    row['hot'] = random.randint(0, 10) if is_attack else random.randint(0, 2)
    row['num_failed_logins'] = random.randint(0, 5) if is_attack and random.random() < 0.3 else 0
    row['logged_in'] = random.randint(0, 1)
    row['num_compromised'] = random.randint(0, 5) if is_attack and random.random() < 0.4 else 0
    row['root_shell'] = random.randint(0, 1) if is_attack and random.random() < 0.2 else 0
    row['su_attempted'] = random.randint(0, 1) if is_attack and random.random() < 0.1 else 0
    row['num_root'] = random.randint(0, 7) if is_attack and random.random() < 0.3 else 0
    row['num_file_creations'] = random.randint(0, 8) if is_attack and random.random() < 0.2 else random.randint(0, 2)
    row['num_shells'] = random.randint(0, 3) if is_attack and random.random() < 0.2 else 0
    row['num_access_files'] = random.randint(0, 5) if is_attack and random.random() < 0.3 else random.randint(0, 1)
    row['num_outbound_cmds'] = random.randint(0, 1) if is_attack and random.random() < 0.1 else 0
    row['is_host_login'] = random.randint(0, 1) if is_attack and random.random() < 0.05 else 0
    row['is_guest_login'] = random.randint(0, 1) if is_attack and random.random() < 0.1 else 0
    
    # Connection statistics
    row['count'] = random.randint(1, 500)
    row['srv_count'] = random.randint(1, 300)
    
    # Rate features
    if is_attack and random.random() < 0.4:
        row['serror_rate'] = round(random.uniform(0.7, 1.0), 3)
        row['srv_serror_rate'] = round(random.uniform(0.7, 1.0), 3)
    else:
        row['serror_rate'] = round(random.uniform(0.0, 0.2), 3)
        row['srv_serror_rate'] = round(random.uniform(0.0, 0.2), 3)
    
    if is_attack and random.random() < 0.3:
        row['rerror_rate'] = round(random.uniform(0.7, 1.0), 3)
        row['srv_rerror_rate'] = round(random.uniform(0.7, 1.0), 3)
    else:
        row['rerror_rate'] = round(random.uniform(0.0, 0.2), 3)
        row['srv_rerror_rate'] = round(random.uniform(0.0, 0.2), 3)
    
    # Service features
    row['same_srv_rate'] = round(random.uniform(0.8, 1.0) if not is_attack else random.uniform(0.0, 1.0), 3)
    row['diff_srv_rate'] = round(1.0 - row['same_srv_rate'], 3)
    row['srv_diff_host_rate'] = round(random.uniform(0.0, 0.4), 3)
    
    # Host-based features
    row['dst_host_count'] = random.randint(1, 255)
    row['dst_host_srv_count'] = random.randint(1, min(255, row['dst_host_count']))
    row['dst_host_same_srv_rate'] = round(random.uniform(0.7, 1.0) if not is_attack else random.uniform(0.0, 1.0), 3)
    row['dst_host_diff_srv_rate'] = round(1.0 - row['dst_host_same_srv_rate'], 3)
    row['dst_host_same_src_port_rate'] = round(random.uniform(0.0, 1.0), 3)
    row['dst_host_srv_diff_host_rate'] = round(random.uniform(0.0, 1.0), 3)
    
    # Host error rates
    if is_attack and random.random() < 0.4:
        row['dst_host_serror_rate'] = round(random.uniform(0.7, 1.0), 3)
        row['dst_host_srv_serror_rate'] = round(random.uniform(0.7, 1.0), 3)
    else:
        row['dst_host_serror_rate'] = round(random.uniform(0.0, 0.2), 3)
        row['dst_host_srv_serror_rate'] = round(random.uniform(0.0, 0.2), 3)
    
    if is_attack and random.random() < 0.3:
        row['dst_host_rerror_rate'] = round(random.uniform(0.7, 1.0), 3)
        row['dst_host_srv_rerror_rate'] = round(random.uniform(0.7, 1.0), 3)
    else:
        row['dst_host_rerror_rate'] = round(random.uniform(0.0, 0.2), 3)
        row['dst_host_srv_rerror_rate'] = round(random.uniform(0.0, 0.2), 3)
    
    return row

def generate_test_data(num_samples: int = 100, attack_ratio: float = 0.3) -> pd.DataFrame:
    """
    Generate a test dataset with NSL-KDD features.
    
    Args:
        num_samples: Number of samples to generate
        attack_ratio: Ratio of attack traffic to normal traffic
        
    Returns:
        DataFrame with NSL-KDD features
    """
    data = []
    
    # Generate normal traffic
    normal_samples = int(num_samples * (1 - attack_ratio))
    for _ in range(normal_samples):
        data.append(generate_row(is_attack=False))
    
    # Generate attack traffic
    attack_samples = num_samples - normal_samples
    for _ in range(attack_samples):
        data.append(generate_row(is_attack=True))
    
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Shuffle the data
    df = df.sample(frac=1).reset_index(drop=True)
    
    return df

def main():
    """
    Generate and save sample test data.
    """
    # Generate some test data
    small_dataset = generate_test_data(num_samples=50, attack_ratio=0.3)
    medium_dataset = generate_test_data(num_samples=200, attack_ratio=0.3)
    
    # Save to CSV
    small_dataset.to_csv('nsl_kdd_sample_small.csv', index=False)
    medium_dataset.to_csv('nsl_kdd_sample_medium.csv', index=False)
    
    print(f"Generated small sample dataset with {len(small_dataset)} records")
    print(f"Generated medium sample dataset with {len(medium_dataset)} records")
    print("Files saved as 'nsl_kdd_sample_small.csv' and 'nsl_kdd_sample_medium.csv'")

if __name__ == "__main__":
    main()