"""
Django management command to retrain the phishing detection ML model.

Usage:
    python manage.py retrain_model                 # Full retrain with hyperparameter tuning
    python manage.py retrain_model --quick         # Quick retrain (no tuning)
    python manage.py retrain_model --force         # Deploy even if metrics aren't better
    python manage.py retrain_model --include-feedback  # Include user feedback corrections
    python manage.py retrain_model --samples 5000  # Limit dataset size per class
"""

import os
import sys
import json
import glob
import pickle
import time
from datetime import datetime

from django.core.management.base import BaseCommand
from django.conf import settings

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, RandomizedSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
import xgboost as xgb

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False


FEATURE_NAMES = [
    'having_ip_address', 'long_url', 'shortening_service',
    'having_@_symbol', 'redirection_//_symbol', 'prefix_suffix_seperation',
    'sub_domains', 'https_token', 'age_of_domain', 'dns_record',
    'web_traffic', 'domain_registration_length', 'statistical_report',
    'iframe', 'mouse_over',
    'url_entropy', 'digit_ratio', 'special_char_count',
    'domain_length', 'path_depth', 'tld_suspicious',
    'punycode_detected', 'contains_brand_name', 'cert_check',
    'url_has_login_keywords',
    'data_uri_phishing', 'open_redirect_detection',
    'suspicious_query_string', 'domain_ip_mismatch',
]

MODEL_DIR = os.path.join(settings.BASE_DIR, 'phishingUrlDetectionBackend', 'model')
MODEL_PATH_1 = os.path.join(settings.BASE_DIR, 'phishingUrlDetectionApp', 'ML', 'model', 'XGBoostClassifier.sav')
MODEL_PATH_2 = os.path.join(MODEL_DIR, 'XGBoostClassifier.sav')
METADATA_PATH = os.path.join(MODEL_DIR, 'model_metadata.json')
ML_DIR = os.path.join(os.path.dirname(settings.BASE_DIR), 'ml')
DATASET_PATH = os.path.join(ML_DIR, 'extracted_dataset', 'full_dataset_v2.csv')


class Command(BaseCommand):
    help = 'Retrain the phishing detection ML model'

    def add_arguments(self, parser):
        parser.add_argument('--quick', action='store_true', help='Skip hyperparameter tuning')
        parser.add_argument('--force', action='store_true', help='Deploy even if new model is worse')
        parser.add_argument('--include-feedback', action='store_true', help='Include user feedback data')
        parser.add_argument('--samples', type=int, default=0, help='Max samples per class (0=all)')

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('=' * 60))
        self.stdout.write(self.style.SUCCESS('PhishGuard Model Retraining'))
        self.stdout.write(self.style.SUCCESS('=' * 60))

        # Step 1: Load dataset
        df = self._load_dataset(options['samples'])
        if df is None:
            return

        # Step 2: Optionally include feedback data
        if options['include_feedback']:
            df = self._incorporate_feedback(df)

        # Step 3: Prepare features
        available_features = [f for f in FEATURE_NAMES if f in df.columns]
        X = df[available_features]
        y = df['label']

        self.stdout.write(f"Features: {len(available_features)}")
        self.stdout.write(f"Samples: {len(X)} ({sum(y == 0)} legit, {sum(y == 1)} phishing)")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Step 4: Train models
        quick = options['quick']
        results = {}

        xgb_model = self._train_xgboost(X_train, y_train, quick)
        results['xgboost'] = self._evaluate(xgb_model, X_test, y_test, 'XGBoost')

        rf_model = self._train_random_forest(X_train, y_train, quick)
        results['random_forest'] = self._evaluate(rf_model, X_test, y_test, 'RandomForest')

        lgb_model = None
        if HAS_LIGHTGBM:
            lgb_model = self._train_lightgbm(X_train, y_train, quick)
            results['lightgbm'] = self._evaluate(lgb_model, X_test, y_test, 'LightGBM')

        # Ensemble
        estimators = [('xgb', xgb_model), ('rf', rf_model)]
        if lgb_model:
            estimators.append(('lgb', lgb_model))
        ensemble = VotingClassifier(estimators=estimators, voting='soft')
        ensemble.fit(X_train, y_train)
        results['ensemble'] = self._evaluate(ensemble, X_test, y_test, 'Ensemble')

        # Step 5: Pick best
        best_name = max(results, key=lambda k: results[k]['f1'])
        best_f1 = results[best_name]['f1']
        model_map = {'xgboost': xgb_model, 'random_forest': rf_model,
                     'lightgbm': lgb_model, 'ensemble': ensemble}
        best_model = model_map[best_name]

        self.stdout.write(self.style.SUCCESS(
            f"\nBest model: {best_name} (F1: {best_f1:.4f})"
        ))

        # Step 6: Compare with existing model
        old_f1 = self._get_old_f1()
        if old_f1 is not None and not options['force']:
            if best_f1 <= old_f1:
                self.stdout.write(self.style.WARNING(
                    f"New F1 ({best_f1:.4f}) <= old F1 ({old_f1:.4f}). "
                    f"Use --force to deploy anyway."
                ))
                return
            self.stdout.write(f"Improvement: {old_f1:.4f} -> {best_f1:.4f} (+{best_f1 - old_f1:.4f})")

        # Step 7: Save with versioning
        self._save_model(best_model, best_name, available_features, results, len(df))

        # Step 8: Hot-reload
        self._hot_reload(best_model)

        self.stdout.write(self.style.SUCCESS('\nRetraining complete! Model is live.'))

    def _load_dataset(self, max_samples):
        if not os.path.exists(DATASET_PATH):
            self.stdout.write(self.style.ERROR(
                f"Dataset not found at {DATASET_PATH}. "
                f"Run: python -m ml.build_dataset"
            ))
            return None

        df = pd.read_csv(DATASET_PATH)
        self.stdout.write(f"Loaded dataset: {df.shape}")

        if max_samples > 0:
            legit = df[df['label'] == 0].head(max_samples)
            phish = df[df['label'] == 1].head(max_samples)
            df = pd.concat([legit, phish]).sample(frac=1, random_state=42).reset_index(drop=True)
            self.stdout.write(f"Sampled to {len(df)} rows")

        return df

    def _incorporate_feedback(self, df):
        """Add user-corrected samples from ScanResult feedback."""
        from phishingUrlDetectionApp.models import ScanResult
        from phishingUrlDetectionApp.feature import featureExtraction

        incorrect = ScanResult.objects.filter(
            user_feedback='incorrect',
            feedback_label__isnull=False,
            scan_type='url'
        )
        count = incorrect.count()
        if count == 0:
            self.stdout.write("No user feedback corrections found.")
            return df

        self.stdout.write(f"Incorporating {count} user-corrected samples...")
        new_rows = []
        for scan in incorrect:
            try:
                features = featureExtraction(scan.target)
                label = 1 if scan.feedback_label == 'phishing' else 0
                row = dict(zip(FEATURE_NAMES[:len(features)], features))
                row['label'] = label
                new_rows.append(row)
            except Exception as e:
                self.stdout.write(f"  Skipping {scan.target[:50]}: {e}")

        if new_rows:
            feedback_df = pd.DataFrame(new_rows)
            df = pd.concat([df, feedback_df], ignore_index=True)
            self.stdout.write(f"  Added {len(new_rows)} feedback samples (total: {len(df)})")

        return df

    def _train_xgboost(self, X_train, y_train, quick):
        self.stdout.write("\nTraining XGBoost...")
        if quick:
            model = xgb.XGBClassifier(
                n_estimators=200, max_depth=6, learning_rate=0.1,
                objective='binary:logistic', random_state=42,
                use_label_encoder=False, eval_metric='logloss',
            )
            model.fit(X_train, y_train)
            return model

        param_dist = {
            'n_estimators': [100, 200, 300, 500],
            'max_depth': [4, 6, 8, 10],
            'learning_rate': [0.01, 0.05, 0.1, 0.2],
            'subsample': [0.7, 0.8, 0.9, 1.0],
            'colsample_bytree': [0.7, 0.8, 0.9, 1.0],
        }
        base = xgb.XGBClassifier(objective='binary:logistic', random_state=42,
                                  use_label_encoder=False, eval_metric='logloss')
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        search = RandomizedSearchCV(base, param_dist, n_iter=20, cv=cv,
                                     scoring='f1', random_state=42, n_jobs=-1, verbose=0)
        search.fit(X_train, y_train)
        self.stdout.write(f"  Best CV F1: {search.best_score_:.4f}")
        return search.best_estimator_

    def _train_random_forest(self, X_train, y_train, quick):
        self.stdout.write("Training Random Forest...")
        if quick:
            model = RandomForestClassifier(n_estimators=200, max_depth=15,
                                            random_state=42, n_jobs=-1)
            model.fit(X_train, y_train)
            return model

        param_dist = {
            'n_estimators': [100, 200, 300, 500],
            'max_depth': [10, 15, 20, None],
            'min_samples_split': [2, 5, 10],
            'max_features': ['sqrt', 'log2', None],
        }
        base = RandomForestClassifier(random_state=42, n_jobs=-1)
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        search = RandomizedSearchCV(base, param_dist, n_iter=20, cv=cv,
                                     scoring='f1', random_state=42, n_jobs=-1, verbose=0)
        search.fit(X_train, y_train)
        self.stdout.write(f"  Best CV F1: {search.best_score_:.4f}")
        return search.best_estimator_

    def _train_lightgbm(self, X_train, y_train, quick):
        self.stdout.write("Training LightGBM...")
        if quick:
            model = lgb.LGBMClassifier(n_estimators=200, max_depth=8,
                                        learning_rate=0.1, random_state=42, verbose=-1)
            model.fit(X_train, y_train)
            return model

        param_dist = {
            'n_estimators': [100, 200, 300, 500],
            'max_depth': [4, 6, 8, 10, -1],
            'learning_rate': [0.01, 0.05, 0.1, 0.2],
            'num_leaves': [15, 31, 63, 127],
        }
        base = lgb.LGBMClassifier(random_state=42, verbose=-1)
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        search = RandomizedSearchCV(base, param_dist, n_iter=20, cv=cv,
                                     scoring='f1', random_state=42, n_jobs=-1, verbose=0)
        search.fit(X_train, y_train)
        self.stdout.write(f"  Best CV F1: {search.best_score_:.4f}")
        return search.best_estimator_

    def _evaluate(self, model, X_test, y_test, name):
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else y_pred
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'roc_auc': roc_auc_score(y_test, y_proba),
        }
        self.stdout.write(
            f"  {name}: F1={metrics['f1']:.4f} | Recall={metrics['recall']:.4f} | AUC={metrics['roc_auc']:.4f}"
        )
        return metrics

    def _get_old_f1(self):
        if not os.path.exists(METADATA_PATH):
            return None
        try:
            with open(METADATA_PATH, 'r') as f:
                meta = json.load(f)
            model_type = meta.get('model_type', '')
            return meta.get('metrics', {}).get(model_type, {}).get('f1')
        except Exception:
            return None

    def _save_model(self, model, model_type, feature_names, results, dataset_size):
        os.makedirs(MODEL_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(MODEL_PATH_1), exist_ok=True)

        # Save versioned copy
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        versioned_path = os.path.join(MODEL_DIR, f'XGBoostClassifier_{timestamp}.sav')
        for path in [MODEL_PATH_1, MODEL_PATH_2, versioned_path]:
            with open(path, 'wb') as f:
                pickle.dump(model, f)

        self.stdout.write(f"Model saved to {MODEL_PATH_2}")
        self.stdout.write(f"Versioned copy: {versioned_path}")

        # Clean up old versions (keep last 3)
        pattern = os.path.join(MODEL_DIR, 'XGBoostClassifier_*.sav')
        versions = sorted(glob.glob(pattern))
        while len(versions) > 3:
            old = versions.pop(0)
            os.remove(old)
            self.stdout.write(f"Removed old version: {os.path.basename(old)}")

        # Save metadata
        metadata = {
            'model_type': model_type,
            'n_features': len(feature_names),
            'feature_names': feature_names,
            'metrics': {k: {mk: round(mv, 4) for mk, mv in v.items()} for k, v in results.items()},
            'dataset_size': dataset_size,
            'trained_at': datetime.now().isoformat(),
        }
        with open(METADATA_PATH, 'w') as f:
            json.dump(metadata, f, indent=2)

    def _hot_reload(self, model):
        """Update the model in the running Django process."""
        try:
            from phishingUrlDetectionApp.apps import PhishingurldetectionappConfig
            PhishingurldetectionappConfig.model = model
            n = getattr(model, 'n_features_in_', 'unknown')
            self.stdout.write(self.style.SUCCESS(f"Hot-reloaded model ({n} features)"))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"Hot-reload failed: {e}. Restart Django to load."))
