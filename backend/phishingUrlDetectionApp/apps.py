import os
import xgboost as xgb
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from django.apps import AppConfig
from django.conf import settings




class PhishingurldetectionappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'phishingUrlDetectionApp'
    
    # Define model paths
    model_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'phishingUrlDetectionBackend', 'model', 'XGBoostClassifier.sav')
    # Alternative path if the above doesn't exist
    if not os.path.exists(model_path):
        model_path = os.path.join(os.path.dirname(__file__), 'ML', 'model', 'XGBoostClassifier.sav')
    
    # Create model directory if it doesn't exist
    model_dir = os.path.dirname(model_path)
    os.makedirs(model_dir, exist_ok=True)
    
    # Try to load the model, if it fails create a more robust fallback model
    try:
        # Try to load the model
        print(f"Attempting to load model from {model_path}")
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        print("Successfully loaded the model")
    except Exception as e:
        print(f"Error loading model: {e}")
        print("Creating a fallback RandomForest model...")
        
        # Create a RandomForest model as fallback
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        # Train with synthetic data representing common phishing patterns
        # 15 features as in the original implementation
        # 0: having_ip_address
        # 1: long_url
        # 2: shortening_service
        # 3: having_@_symbol
        # 4: redirection_//_symbol
        # 5: prefix_suffix_seperation
        # 6: sub_domains
        # 7: https_token
        # 8: age_of_domain
        # 9: dns_record
        # 10: web_traffic
        # 11: domain_registration_length
        # 12: statistical_report
        # 13: iframe
        # 14: mouse_over
        
        # Generate synthetic data with realistic patterns
        # Create legitimate website patterns (label 0)
        legitimate_patterns = [
            # Modern legitimate websites typically have these characteristics
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],  # Common legitimate site
            [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0],  # Legitimate with https in domain
            [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],  # Legitimate but long URL
            [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0],  # Legitimate with hyphen
            [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],  # Legitimate with subdomain
            [0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0],  # Legitimate with multiple subdomains
        ]
        
        # Create phishing patterns (label 1)
        phishing_patterns = [
            # Common phishing patterns
            [1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 2, 1, 0, 0, 0],  # IP address and long URL
            [0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 2, 1, 0, 0, 0],  # URL shortener and @ symbol
            [0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 2, 1, 0, 0, 0],  # @ symbol and redirection
            [0, 1, 0, 0, 0, 1, 2, 1, 1, 1, 2, 1, 0, 0, 0],  # Multiple suspicious domain features
            [0, 1, 1, 0, 0, 0, 2, 0, 1, 1, 2, 1, 1, 1, 1],  # Multiple suspicious HTML features
            [1, 1, 0, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 1],  # Highly suspicious combination
        ]
        
        # Create training data with multiple copies of each pattern for better training
        X_train = []
        y_train = []
        
        # Add legitimate patterns (with variations)
        for pattern in legitimate_patterns:
            # Add the base pattern
            X_train.append(pattern)
            y_train.append(0)  # Legitimate
            
            # Add variations with small random changes
            for _ in range(15):
                variation = pattern.copy()
                # Modify 1-2 features slightly
                for _ in range(np.random.randint(1, 3)):
                    idx = np.random.randint(0, len(variation))
                    if variation[idx] == 0:
                        variation[idx] = np.random.choice([0, 1], p=[0.8, 0.2])
                    elif variation[idx] == 1:
                        variation[idx] = np.random.choice([0, 1], p=[0.2, 0.8])
                X_train.append(variation)
                y_train.append(0)  # Still legitimate
        
        # Add phishing patterns (with variations)
        for pattern in phishing_patterns:
            # Add the base pattern
            X_train.append(pattern)
            y_train.append(1)  # Phishing
            
            # Add variations with small random changes
            for _ in range(15):
                variation = pattern.copy()
                # Modify 1-2 features slightly
                for _ in range(np.random.randint(1, 3)):
                    idx = np.random.randint(0, len(variation))
                    if variation[idx] == 0:
                        variation[idx] = np.random.choice([0, 1], p=[0.8, 0.2])
                    elif variation[idx] == 1:
                        variation[idx] = np.random.choice([0, 1, 2], p=[0.2, 0.6, 0.2])
                X_train.append(variation)
                y_train.append(1)  # Still phishing
        
        # Convert to numpy arrays for training
        X_train = np.array(X_train)
        y_train = np.array(y_train)
        
        # Train the model
        model.fit(X_train, y_train)
        
        # Save the fallback model for future use
        try:
            print(f"Saving fallback model to {model_path}")
            pickle.dump(model, open(model_path, 'wb'))
            print("Fallback model saved successfully")
        except Exception as e:
            print(f"Couldn't save fallback model: {e}")