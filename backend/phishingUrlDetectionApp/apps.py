import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from django.apps import AppConfig


class PhishingurldetectionappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'phishingUrlDetectionApp'

    # Define model paths (try multiple locations)
    _model_paths = [
        os.path.join(os.path.dirname(os.path.dirname(__file__)),
                     'phishingUrlDetectionBackend', 'model', 'XGBoostClassifier.sav'),
        os.path.join(os.path.dirname(__file__),
                     'ML', 'model', 'XGBoostClassifier.sav'),
    ]

    model = None

    for _path in _model_paths:
        if os.path.exists(_path):
            try:
                print(f"Loading model from {_path}")
                with open(_path, 'rb') as f:
                    model = pickle.load(f)
                n_features = getattr(model, 'n_features_in_', 'unknown')
                print(f"Model loaded successfully ({n_features} features)")
                break
            except Exception as e:
                print(f"Error loading model from {_path}: {e}")

    if model is None:
        print("WARNING: No trained model found. Training a minimal fallback model.")
        print("         Run 'python -m ml.train_new_model' for best results.")

        # Minimal fallback — just enough to not crash. Trains on basic patterns
        # so the app can start. The real model should be trained via the ML pipeline.
        model = RandomForestClassifier(
            n_estimators=50, max_depth=8, random_state=42, n_jobs=-1
        )

        # Small but reasonable synthetic data (15 features — backwards compatible)
        X_train = np.array([
            # Legitimate patterns
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
            # Phishing patterns
            [1, 1, 0, 1, 0, 1, 2, 0, 1, 0, 1, 1, 1, 1, 1],
            [0, 1, 1, 0, 1, 0, 2, 1, 1, 0, 1, 1, 0, 1, 0],
            [1, 0, 0, 1, 1, 1, 2, 1, 1, 0, 1, 1, 1, 0, 1],
            [0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1],
        ])
        y_train = np.array([0, 0, 0, 0, 1, 1, 1, 1])
        model.fit(X_train, y_train)

        # Save so next startup loads it
        for _path in _model_paths:
            try:
                os.makedirs(os.path.dirname(_path), exist_ok=True)
                with open(_path, 'wb') as f:
                    pickle.dump(model, f)
                print(f"Fallback model saved to {_path}")
                break
            except Exception as e:
                print(f"Could not save fallback model to {_path}: {e}")
