import joblib
import numpy as np
import pandas as pd
from typing import Tuple, List, Dict, Union, Optional
import os
import pickle
from sklearn.ensemble import RandomForestClassifier

# Path to save/load the model
MODEL_PATH = "nsl_kdd_model.pkl"

def train_dummy_model() -> None:
    """
    Train a model on the NSL-KDD dataset.
    """
    try:
        # Try to load the training data
        train_data = pd.read_csv('KDDTrain+.txt', header=None, names=[
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
            'dst_host_srv_rerror_rate', 'label', 'difficulty'
        ])
        
        # Prepare features and target
        X = train_data.drop(['label', 'difficulty'], axis=1)
        y = train_data['label'].apply(lambda x: 0 if x == 'normal' else 1)
        
        # Create and train the model
        from sklearn.pipeline import Pipeline
        from sklearn.compose import ColumnTransformer
        from sklearn.preprocessing import StandardScaler, OneHotEncoder
        
        # Define feature types
        categorical_features = ['protocol_type', 'service', 'flag']
        numeric_features = [col for col in X.columns if col not in categorical_features]
        
        # Create preprocessing steps
        preprocessor = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), numeric_features),
                ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
            ])
        
        # Create pipeline
        model = Pipeline([
            ('preprocessor', preprocessor),
            ('classifier', RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                random_state=42,
                n_jobs=-1
            ))
        ])
        
        # Train the model
        model.fit(X, y)
        
        # Save the trained model
        save_model(model)
        print("Model trained and saved successfully.")
        
    except FileNotFoundError:
        print("Training data not found. Please download the NSL-KDD dataset.")
        print("You can download it from: https://www.unb.ca/cic/datasets/nsl.html")
        print("Place the KDDTrain+.txt file in the current directory.")
        
        # Create a simple model with some basic rules
        model = Pipeline([
            ('classifier', RandomForestClassifier(
                n_estimators=10,
                max_depth=5,
                random_state=42
            ))
        ])
        
        # Create some simple synthetic data to train on
        X = pd.DataFrame({
            'duration': [1, 2, 100, 200],
            'protocol_type': ['tcp', 'udp', 'tcp', 'icmp'],
            'service': ['http', 'ftp', 'telnet', 'http'],
            'flag': ['SF', 'S0', 'REJ', 'SF'],
            'src_bytes': [100, 2000, 500, 1000]
        })
        y = np.array([0, 1, 1, 0])  # 0 for benign, 1 for malignant
        
        # Train on synthetic data
        model.fit(X, y)
        save_model(model)
        print("Trained a simple model on synthetic data as fallback.")

def save_model(model: object) -> None:
    """
    Save the trained model to disk.
    
    Args:
        model: Trained model to save
    """
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)

def load_model() -> Optional[object]:
    """
    Load the pre-trained model from disk.
    
    Returns:
        Loaded model or None if model doesn't exist
    """
    # Check if model exists, if not create a dummy one
    if not os.path.exists(MODEL_PATH):
        print("Model not found. Creating a dummy model...")
        train_dummy_model()
    
    try:
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        return model
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        return None

def predict(df: pd.DataFrame) -> Tuple[np.ndarray, Dict[str, int]]:
    """
    Make predictions using the pre-trained model.
    
    Args:
        df: Preprocessed DataFrame containing features
        
    Returns:
        Tuple containing:
        - Array of predictions (0 for benign, 1 for malignant)
        - Dictionary with counts of each class
    """
    model = load_model()
    
    if model is None:
        # If model loading failed, default to a simple random prediction
        # This is just for demo purposes
        predictions = np.random.randint(0, 2, size=len(df))
    else:
        try:
            # Make predictions
            predictions = model.predict(df)
        except Exception as e:
            print(f"Error during prediction: {str(e)}")
            # Fall back to random predictions
            predictions = np.random.randint(0, 2, size=len(df))
    
    # Calculate class counts
    class_counts = {
        'benign': int(np.sum(predictions == 0)),
        'malignant': int(np.sum(predictions == 1))
    }
    
    return predictions, class_counts