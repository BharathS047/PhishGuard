import pandas as pd
import numpy as np
import os
import pickle
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import xgboost as xgb

print("Starting model training process...")

# Path to datasets
phishing_data_path = os.path.join('ml', 'extracted_dataset', 'extracted_phishing_dataset.csv')
legitimate_data_path = os.path.join('ml', 'extracted_dataset', 'extracted_legitmate_dataset.csv')

# Load datasets
print("Loading datasets...")
try:
    phishing_data = pd.read_csv(phishing_data_path)
    legitimate_data = pd.read_csv(legitimate_data_path)
    
    print(f"Phishing data shape: {phishing_data.shape}")
    print(f"Legitimate data shape: {legitimate_data.shape}")
    
    # Add labels
    phishing_data['label'] = 1  # 1 for phishing
    legitimate_data['label'] = 0  # 0 for legitimate
    
    # Combine datasets
    full_dataset = pd.concat([phishing_data, legitimate_data])
    
    # Shuffle the data
    full_dataset = full_dataset.sample(frac=1).reset_index(drop=True)
    
    # Prepare features and labels
    X = full_dataset.drop('label', axis=1)
    y = full_dataset['label']
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print(f"Training data shape: {X_train.shape}")
    print(f"Test data shape: {X_test.shape}")
    
    # Train XGBoost model
    print("Training XGBoost model...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        objective='binary:logistic',
        random_state=42,
        use_label_encoder=False,
        eval_metric='logloss'
    )
    
    xgb_model.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = xgb_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"Model Performance:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    
    # Save model to the two identified locations
    model_path1 = os.path.join('backend', 'phishingUrlDetectionApp', 'ML', 'model', 'XGBoostClassifier.sav')
    model_path2 = os.path.join('backend', 'phishingUrlDetectionBackend', 'model', 'XGBoostClassifier.sav')
    
    # Ensure directories exist
    os.makedirs(os.path.dirname(model_path1), exist_ok=True)
    os.makedirs(os.path.dirname(model_path2), exist_ok=True)
    
    # Save model at both locations
    pickle.dump(xgb_model, open(model_path1, 'wb'))
    pickle.dump(xgb_model, open(model_path2, 'wb'))
    
    print(f"Model saved successfully to:")
    print(f" - {model_path1}")
    print(f" - {model_path2}")
    
except Exception as e:
    print(f"Error during model training: {e}") 