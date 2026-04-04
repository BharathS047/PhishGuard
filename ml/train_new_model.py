"""
Train phishing URL detection model (v2).

Uses the 25-feature dataset built by build_dataset.py.
Trains XGBoost, LightGBM, and RandomForest, then creates a soft-voting
ensemble for the best accuracy.

Usage:
    python -m ml.train_new_model          # Train on full_dataset_v2.csv
    python -m ml.train_new_model --quick  # Quick train (no hyperparameter tuning)
"""

import os
import sys
import pickle
import argparse
import numpy as np
import pandas as pd
from sklearn.model_selection import (
    train_test_split, StratifiedKFold, RandomizedSearchCV
)
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, classification_report, confusion_matrix
)
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
import xgboost as xgb

# Try to import LightGBM — optional but recommended
try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False
    print("Warning: LightGBM not installed. Install with: pip install lightgbm")
    print("         Falling back to XGBoost + RandomForest ensemble.\n")

# ── Paths ──
ML_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(ML_DIR, 'extracted_dataset')
DATASET_V2 = os.path.join(DATASET_DIR, 'full_dataset_v2.csv')
DATASET_V1_PHISHING = os.path.join(DATASET_DIR, 'extracted_phishing_dataset.csv')
DATASET_V1_LEGIT = os.path.join(DATASET_DIR, 'extracted_legitmate_dataset.csv')

BACKEND_DIR = os.path.join(os.path.dirname(ML_DIR), 'backend')
MODEL_PATH_1 = os.path.join(BACKEND_DIR, 'phishingUrlDetectionApp', 'ML', 'model', 'XGBoostClassifier.sav')
MODEL_PATH_2 = os.path.join(BACKEND_DIR, 'phishingUrlDetectionBackend', 'model', 'XGBoostClassifier.sav')

FEATURE_NAMES_15 = [
    'having_ip_address', 'long_url', 'shortening_service',
    'having_@_symbol', 'redirection_//_symbol', 'prefix_suffix_seperation',
    'sub_domains', 'https_token', 'age_of_domain', 'dns_record',
    'web_traffic', 'domain_registration_length', 'statistical_report',
    'iframe', 'mouse_over',
]

FEATURE_NAMES_25 = FEATURE_NAMES_15 + [
    'url_entropy', 'digit_ratio', 'special_char_count',
    'domain_length', 'path_depth', 'tld_suspicious',
    'punycode_detected', 'contains_brand_name', 'cert_check',
    'url_has_login_keywords',
]

FEATURE_NAMES_29 = FEATURE_NAMES_25 + [
    'data_uri_phishing', 'open_redirect_detection',
    'suspicious_query_string', 'domain_ip_mismatch',
]


def load_dataset():
    """Load the best available dataset."""
    # Prefer v2 (25 features, larger)
    if os.path.exists(DATASET_V2):
        print(f"Loading v2 dataset from {DATASET_V2}")
        df = pd.read_csv(DATASET_V2)
        print(f"  Shape: {df.shape}")
        print(f"  Label distribution:\n{df['label'].value_counts().to_string()}")
        return df

    # Fall back to v1 (15 features, 2000 samples)
    print("v2 dataset not found. Falling back to v1 dataset (15 features).")
    print("Run 'python -m ml.build_dataset' first for best results.\n")

    if not os.path.exists(DATASET_V1_PHISHING) or not os.path.exists(DATASET_V1_LEGIT):
        print("ERROR: No dataset found. Run build_dataset.py first.")
        sys.exit(1)

    phishing = pd.read_csv(DATASET_V1_PHISHING)
    legit = pd.read_csv(DATASET_V1_LEGIT)

    # Drop non-feature columns if present
    drop_cols = ['protocol', 'domain_name', 'address']
    phishing = phishing.drop(columns=[c for c in drop_cols if c in phishing.columns], errors='ignore')
    legit = legit.drop(columns=[c for c in drop_cols if c in legit.columns], errors='ignore')

    # Add labels if not present
    if 'label' not in phishing.columns:
        phishing['label'] = 1
    if 'label' not in legit.columns:
        legit['label'] = 0

    df = pd.concat([phishing, legit], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"  Shape: {df.shape}")
    return df


def train_xgboost(X_train, y_train, quick=False):
    """Train XGBoost with optional hyperparameter tuning."""
    print("\n--- Training XGBoost ---")

    if quick:
        model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            objective='binary:logistic',
            random_state=42,
            use_label_encoder=False,
            eval_metric='logloss',
            scale_pos_weight=1,
        )
        model.fit(X_train, y_train)
        return model

    # Hyperparameter search
    param_dist = {
        'n_estimators': [100, 200, 300, 500],
        'max_depth': [4, 6, 8, 10],
        'learning_rate': [0.01, 0.05, 0.1, 0.2],
        'subsample': [0.7, 0.8, 0.9, 1.0],
        'colsample_bytree': [0.7, 0.8, 0.9, 1.0],
        'min_child_weight': [1, 3, 5],
        'gamma': [0, 0.1, 0.2],
    }

    base_model = xgb.XGBClassifier(
        objective='binary:logistic',
        random_state=42,
        use_label_encoder=False,
        eval_metric='logloss',
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    search = RandomizedSearchCV(
        base_model, param_dist,
        n_iter=30, cv=cv, scoring='f1',
        random_state=42, n_jobs=-1, verbose=1
    )
    search.fit(X_train, y_train)

    print(f"  Best params: {search.best_params_}")
    print(f"  Best CV F1: {search.best_score_:.4f}")
    return search.best_estimator_


def train_random_forest(X_train, y_train, quick=False):
    """Train RandomForest with optional hyperparameter tuning."""
    print("\n--- Training Random Forest ---")

    if quick:
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_train, y_train)
        return model

    param_dist = {
        'n_estimators': [100, 200, 300, 500],
        'max_depth': [10, 15, 20, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
        'max_features': ['sqrt', 'log2', None],
    }

    base_model = RandomForestClassifier(random_state=42, n_jobs=-1)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    search = RandomizedSearchCV(
        base_model, param_dist,
        n_iter=20, cv=cv, scoring='f1',
        random_state=42, n_jobs=-1, verbose=1
    )
    search.fit(X_train, y_train)

    print(f"  Best params: {search.best_params_}")
    print(f"  Best CV F1: {search.best_score_:.4f}")
    return search.best_estimator_


def train_lightgbm(X_train, y_train, quick=False):
    """Train LightGBM with optional hyperparameter tuning."""
    if not HAS_LIGHTGBM:
        return None

    print("\n--- Training LightGBM ---")

    if quick:
        model = lgb.LGBMClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            random_state=42,
            verbose=-1,
        )
        model.fit(X_train, y_train)
        return model

    param_dist = {
        'n_estimators': [100, 200, 300, 500],
        'max_depth': [4, 6, 8, 10, -1],
        'learning_rate': [0.01, 0.05, 0.1, 0.2],
        'num_leaves': [15, 31, 63, 127],
        'subsample': [0.7, 0.8, 0.9, 1.0],
        'colsample_bytree': [0.7, 0.8, 0.9, 1.0],
    }

    base_model = lgb.LGBMClassifier(random_state=42, verbose=-1)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    search = RandomizedSearchCV(
        base_model, param_dist,
        n_iter=20, cv=cv, scoring='f1',
        random_state=42, n_jobs=-1, verbose=1
    )
    search.fit(X_train, y_train)

    print(f"  Best params: {search.best_params_}")
    print(f"  Best CV F1: {search.best_score_:.4f}")
    return search.best_estimator_


def evaluate_model(model, X_test, y_test, name="Model"):
    """Evaluate a model and print metrics."""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else y_pred

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)

    print(f"\n{'=' * 50}")
    print(f"  {name} Results")
    print(f"{'=' * 50}")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}  (catching phishing)")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  ROC-AUC:   {roc_auc:.4f}")
    print(f"\n  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"    TN={cm[0][0]:5d}  FP={cm[0][1]:5d}")
    print(f"    FN={cm[1][0]:5d}  TP={cm[1][1]:5d}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    return {'accuracy': accuracy, 'precision': precision, 'recall': recall,
            'f1': f1, 'roc_auc': roc_auc}


def print_feature_importance(model, feature_names, top_n=15):
    """Print top feature importances."""
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
    elif hasattr(model, 'estimators_') and hasattr(model, 'named_estimators_'):
        # VotingClassifier — use first estimator that has importances
        for name, est in model.named_estimators_.items():
            if hasattr(est, 'feature_importances_'):
                importances = est.feature_importances_
                break
        else:
            return
    else:
        return

    indices = np.argsort(importances)[::-1][:top_n]
    print(f"\n  Top {top_n} Feature Importances:")
    for i, idx in enumerate(indices):
        if idx < len(feature_names):
            print(f"    {i+1:2d}. {feature_names[idx]:30s} {importances[idx]:.4f}")


def main():
    parser = argparse.ArgumentParser(description='Train phishing URL detection model')
    parser.add_argument('--quick', action='store_true',
                        help='Quick training without hyperparameter tuning')
    args = parser.parse_args()

    print("=" * 60)
    print("PhishGuard ML Model Training (v2)")
    print("=" * 60)

    # Load dataset
    df = load_dataset()

    # Determine feature set based on dataset columns
    if 'data_uri_phishing' in df.columns:
        feature_names = FEATURE_NAMES_29
        print(f"\nUsing 29-feature dataset")
    elif 'url_entropy' in df.columns:
        feature_names = FEATURE_NAMES_25
        print(f"\nUsing 25-feature dataset")
    else:
        feature_names = FEATURE_NAMES_15
        print(f"\nUsing 15-feature dataset (run build_dataset.py for 29 features)")

    # Only keep feature columns that exist
    available_features = [f for f in feature_names if f in df.columns]
    X = df[available_features]
    y = df['label']

    print(f"Features: {len(available_features)}")
    print(f"Samples: {len(X)} ({sum(y == 0)} legitimate, {sum(y == 1)} phishing)")

    # Train-test split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Training set: {len(X_train)} | Test set: {len(X_test)}")

    # Train individual models
    xgb_model = train_xgboost(X_train, y_train, quick=args.quick)
    rf_model = train_random_forest(X_train, y_train, quick=args.quick)
    lgb_model = train_lightgbm(X_train, y_train, quick=args.quick)

    # Evaluate individual models
    results = {}
    results['xgboost'] = evaluate_model(xgb_model, X_test, y_test, "XGBoost")
    results['random_forest'] = evaluate_model(rf_model, X_test, y_test, "Random Forest")
    if lgb_model:
        results['lightgbm'] = evaluate_model(lgb_model, X_test, y_test, "LightGBM")

    # Create ensemble
    print("\n--- Creating Soft-Voting Ensemble ---")
    estimators = [('xgb', xgb_model), ('rf', rf_model)]
    if lgb_model:
        estimators.append(('lgb', lgb_model))

    ensemble = VotingClassifier(estimators=estimators, voting='soft')
    ensemble.fit(X_train, y_train)
    results['ensemble'] = evaluate_model(ensemble, X_test, y_test, "Ensemble")

    # Pick the best model (by F1 score, prioritizing recall)
    best_name = max(results, key=lambda k: results[k]['f1'])
    best_result = results[best_name]

    print(f"\n{'*' * 60}")
    print(f"  BEST MODEL: {best_name}")
    print(f"  F1: {best_result['f1']:.4f} | Recall: {best_result['recall']:.4f} | AUC: {best_result['roc_auc']:.4f}")
    print(f"{'*' * 60}")

    # Select model to save
    model_map = {
        'xgboost': xgb_model,
        'random_forest': rf_model,
        'lightgbm': lgb_model,
        'ensemble': ensemble,
    }
    best_model = model_map[best_name]

    # Print feature importances
    print_feature_importance(best_model, available_features)

    # Save model
    for path in [MODEL_PATH_1, MODEL_PATH_2]:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump(best_model, f)
        print(f"\nModel saved to: {path}")

    # Also save metadata
    metadata = {
        'model_type': best_name,
        'n_features': len(available_features),
        'feature_names': available_features,
        'metrics': {k: {mk: round(mv, 4) for mk, mv in v.items()} for k, v in results.items()},
        'dataset_size': len(df),
        'trained_at': pd.Timestamp.now().isoformat(),
    }
    metadata_path = os.path.join(os.path.dirname(MODEL_PATH_2), 'model_metadata.json')
    import json
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to: {metadata_path}")

    print("\nDone! Restart the Django server to load the new model.")


if __name__ == '__main__':
    main()
