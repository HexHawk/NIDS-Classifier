import pandas as pd
import numpy as np
from typing import Tuple, List, Dict, Optional

# Define the required features based on the NSL-KDD dataset
# This is a subset of columns that our model requires
REQUIRED_FEATURES = [
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

# Categorical features that need to be one-hot encoded
CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']

def validate_csv(file_path: str) -> Tuple[bool, str, Optional[pd.DataFrame]]:
    """
    Validate that the uploaded CSV file contains all required features.
    
    Args:
        file_path: Path to the CSV file
        
    Returns:
        Tuple containing:
        - boolean indicating if the file is valid
        - error message or success message
        - DataFrame if valid, None otherwise
    """
    try:
        # Try to read the CSV file
        df = pd.read_csv(file_path)
        
        # Check if all required features are present
        missing_features = [feature for feature in REQUIRED_FEATURES if feature not in df.columns]
        
        if missing_features:
            return False, f"Missing required features: {', '.join(missing_features)}", None
        
        # Check if there are any rows
        if len(df) == 0:
            return False, "The CSV file is empty", None
            
        return True, "CSV file is valid", df
        
    except Exception as e:
        return False, f"Error reading CSV file: {str(e)}", None

def preprocess_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Preprocess the data for prediction:
    - Handle missing values
    - Perform one-hot encoding for categorical features
    - Scale numerical features
    
    Args:
        df: DataFrame containing the features
        
    Returns:
        Preprocessed DataFrame ready for prediction
    """
    # Make a copy to avoid modifying the original
    df_processed = df.copy()
    
    # Handle missing values
    for col in df_processed.columns:
        if col in CATEGORICAL_FEATURES:
            df_processed[col] = df_processed[col].fillna('unknown')
        else:
            df_processed[col] = df_processed[col].fillna(0)
            
    # Create one-hot encoded features while keeping original categorical columns
    df_encoded = df_processed.copy()
    
    # One-hot encode categorical features
    for feature in CATEGORICAL_FEATURES:
        # Get dummies for each categorical feature
        dummies = pd.get_dummies(
            df_processed[feature],
            prefix=feature,
            drop_first=False,
            dummy_na=False
        )
        # Add the dummies to the dataframe
        df_encoded = pd.concat([df_encoded, dummies], axis=1)
    
    # Check if the model requires specific one-hot encoded columns
    # and add any missing columns with zeros (happens when categorical values in test data
    # weren't present in training data)
    required_encoded_columns = {
        'protocol_type_tcp': 0,
        'protocol_type_udp': 0,
        'protocol_type_icmp': 0,
        # Add more based on your training data
    }
    
    # Add any missing columns needed by the model
    for col, default_val in required_encoded_columns.items():
        if col not in df_encoded.columns:
            df_encoded[col] = default_val
    
    # Simple feature scaling - Min-Max scaling between 0 and 1
    # Only scale numeric columns, excluding both original categorical and one-hot encoded columns
    numeric_cols = [col for col in df_encoded.columns if col not in CATEGORICAL_FEATURES and 
                   not any(col.startswith(f"{f}_") for f in CATEGORICAL_FEATURES)]
    
    for col in numeric_cols:
        max_val = df_encoded[col].max()
        min_val = df_encoded[col].min()
        if max_val > min_val:  # Avoid division by zero
            df_encoded[col] = (df_encoded[col] - min_val) / (max_val - min_val)
    
    return df_encoded

def split_results(df: pd.DataFrame, predictions: np.ndarray) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Split the original dataframe into benign and malignant based on predictions.
    
    Args:
        df: Original DataFrame
        predictions: Array of predictions (0 for benign, 1 for malignant)
        
    Returns:
        Tuple containing:
        - DataFrame with benign traffic
        - DataFrame with malignant traffic
    """
    # Add prediction column
    df_with_predictions = df.copy()
    df_with_predictions['prediction'] = ['benign' if p == 0 else 'malignant' for p in predictions]
    
    # Split into benign and malignant
    benign_df = df_with_predictions[df_with_predictions['prediction'] == 'benign']
    malignant_df = df_with_predictions[df_with_predictions['prediction'] == 'malignant']
    
    return benign_df, malignant_df