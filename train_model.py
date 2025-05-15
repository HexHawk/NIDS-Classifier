import os
import numpy as np
import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle
from typing import Tuple, Dict

# Constants
MODEL_PATH = "nsl_kdd_model.pkl"
RANDOM_STATE = 42

# Features used in the NSL-KDD dataset
CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']
NUMERIC_FEATURES = [
    'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 
    'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 
    'num_shells', 'num_access_files', 'num_outbound_cmds', 
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 
    'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

def load_data(data_path: str) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Load and prepare the NSL-KDD dataset.
    
    Args:
        data_path: Path to the NSL-KDD CSV file
        
    Returns:
        Tuple containing:
        - DataFrame with features
        - Series with target labels
    """
    # Column names for the NSL-KDD dataset
    columns = [
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
    ]
    
    # Load the dataset
    df = pd.read_csv(data_path, names=columns)
    
    # Extract features and target
    X = df[CATEGORICAL_FEATURES + NUMERIC_FEATURES]
    
    # Convert labels to binary (normal=0, attack=1)
    y = df['label'].apply(lambda x: 0 if x == 'normal' else 1)
    
    return X, y

def create_preprocessing_pipeline() -> ColumnTransformer:
    """
    Create a preprocessing pipeline for the data.
    
    Returns:
        ColumnTransformer with preprocessing steps
    """
    # Create preprocessors for different column types
    categorical_transformer = OneHotEncoder(handle_unknown='ignore')
    numeric_transformer = StandardScaler()
    
    # Combine the preprocessors in a column transformer
    preprocessor = ColumnTransformer(
        transformers=[
            ('cat', categorical_transformer, CATEGORICAL_FEATURES),
            ('num', numeric_transformer, NUMERIC_FEATURES)
        ],
        remainder='drop'  # Drop any columns not specified
    )
    
    return preprocessor

def train_model(X: pd.DataFrame, y: pd.Series) -> Tuple[Pipeline, Dict[str, float]]:
    """
    Train a RandomForest classifier on the NSL-KDD dataset.
    
    Args:
        X: DataFrame with features
        y: Series with target labels
        
    Returns:
        Tuple containing:
        - Trained pipeline
        - Dictionary with performance metrics
    """
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )
    
    # Create the preprocessing pipeline
    preprocessor = create_preprocessing_pipeline()
    
    # Create and train the pipeline
    pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=RANDOM_STATE,
            n_jobs=-1  # Use all available cores
        ))
    ])
    
    # Train the model
    pipeline.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = pipeline.predict(X_test)
    
    # Calculate metrics
    metrics = {
        'accuracy': np.mean(y_pred == y_test),
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
        'classification_report': classification_report(y_test, y_pred, output_dict=True)
    }
    
    return pipeline, metrics

def save_model(model: Pipeline, metrics: Dict) -> None:
    """
    Save the trained model and metrics to disk.
    
    Args:
        model: Trained model pipeline
        metrics: Dictionary with performance metrics
    """
    # Save the model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    
    # Save the metrics
    with open('model_metrics.pkl', 'wb') as f:
        pickle.dump(metrics, f)
    
    print(f"Model saved to {MODEL_PATH}")
    print(f"Model accuracy: {metrics['accuracy']:.4f}")

def main(data_path: str = 'KDDTrain+.txt') -> None:
    """
    Main function to train and save the model.
    
    Args:
        data_path: Path to the NSL-KDD dataset
    """
    if not os.path.exists(data_path):
        print(f"Dataset not found at {data_path}")
        print("Please download the NSL-KDD dataset and place it in the correct location.")
        print("The dataset can be downloaded from: https://www.unb.ca/cic/datasets/nsl.html")
        return
    
    print("Loading data...")
    X, y = load_data(data_path)
    
    print("Training model...")
    model, metrics = train_model(X, y)
    
    print("Saving model...")
    save_model(model, metrics)
    
    print("Done!")

if __name__ == "__main__":
    main()