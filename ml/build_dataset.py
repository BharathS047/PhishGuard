"""
Dataset builder for phishing URL detection.

Downloads phishing URLs from PhishTank and legitimate domains from Tranco,
then extracts features using the fixed feature extraction pipeline.

Usage:
    python -m ml.build_dataset                  # Run from project root
    python -m ml.build_dataset --samples 5000   # Limit samples per class
    python -m ml.build_dataset --resume         # Resume from checkpoint
"""

import os
import sys
import csv
import json
import time
import argparse
import requests
import zipfile
import io
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Add backend directory to path so we can import feature extraction
# Works whether run as `python -m ml.build_dataset` or `python ml/build_dataset.py`
_this_dir = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_this_dir)
BACKEND_DIR = os.path.join(PROJECT_ROOT, 'backend')
sys.path.insert(0, BACKEND_DIR)
sys.path.insert(0, PROJECT_ROOT)

# We import feature extraction directly — no Django setup needed
from phishingUrlDetectionApp.feature import featureExtraction, TOTAL_FEATURES

# ── Configuration ──
DATASET_DIR = os.path.join(os.path.dirname(__file__), 'extracted_dataset')
CACHE_DIR = os.path.join(os.path.dirname(__file__), 'cache')
CHECKPOINT_FILE = os.path.join(CACHE_DIR, 'build_checkpoint.json')
OUTPUT_FILE = os.path.join(DATASET_DIR, 'full_dataset_v2.csv')

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
    # Missing attack features (26-29)
    'data_uri_phishing', 'open_redirect_detection',
    'suspicious_query_string', 'domain_ip_mismatch',
]

# Maximum number of worker threads for feature extraction
MAX_WORKERS = 8

# Delay between WHOIS lookups to avoid rate limiting (seconds)
WHOIS_DELAY = 0.5


def download_phishtank_urls(max_urls=10000):
    """Download verified phishing URLs from PhishTank."""
    cache_file = os.path.join(CACHE_DIR, 'phishtank_urls.json')

    # Use cached file if it exists and is less than 24 hours old
    if os.path.exists(cache_file):
        age = time.time() - os.path.getmtime(cache_file)
        if age < 86400:
            print(f"  Using cached PhishTank data ({len(json.load(open(cache_file)))} URLs)")
            with open(cache_file, 'r') as f:
                return json.load(f)[:max_urls]

    print("  Downloading PhishTank database...")
    try:
        url = 'https://data.phishtank.com/data/online-valid.json'
        resp = requests.get(url, timeout=120)
        if resp.status_code == 200:
            data = resp.json()
            urls = [entry['url'] for entry in data if 'url' in entry]
            print(f"  Downloaded {len(urls)} phishing URLs from PhishTank")

            # Cache for reuse
            with open(cache_file, 'w') as f:
                json.dump(urls, f)

            return urls[:max_urls]
        else:
            print(f"  PhishTank download failed: HTTP {resp.status_code}")
    except Exception as e:
        print(f"  PhishTank download error: {e}")

    # Fallback: try OpenPhish
    print("  Trying OpenPhish as fallback...")
    try:
        resp = requests.get('https://openphish.com/feed.txt', timeout=30)
        if resp.status_code == 200:
            urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
            print(f"  Downloaded {len(urls)} URLs from OpenPhish")
            with open(cache_file, 'w') as f:
                json.dump(urls, f)
            return urls[:max_urls]
    except Exception as e:
        print(f"  OpenPhish download error: {e}")

    return []


def download_tranco_domains(max_domains=10000):
    """Download legitimate domains from Tranco top-1M list."""
    cache_file = os.path.join(CACHE_DIR, 'tranco_top1m.csv')

    # Download if not cached or stale
    if not os.path.exists(cache_file) or (time.time() - os.path.getmtime(cache_file) > 86400):
        print("  Downloading Tranco top-1M list...")
        try:
            resp = requests.get('https://tranco-list.eu/top-1m.csv.zip', timeout=60)
            if resp.status_code == 200:
                with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                    names = zf.namelist()
                    with zf.open(names[0]) as src, open(cache_file, 'wb') as dst:
                        dst.write(src.read())
                print("  Tranco list downloaded")
            else:
                print(f"  Tranco download failed: HTTP {resp.status_code}")
                if not os.path.exists(cache_file):
                    return []
        except Exception as e:
            print(f"  Tranco download error: {e}")
            if not os.path.exists(cache_file):
                return []

    # Parse the CSV — take a spread from different rankings
    domains = []
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 2:
                    domains.append(parts[1])
    except Exception as e:
        print(f"  Error reading Tranco list: {e}")
        return []

    # Sample from different tiers for variety
    import random
    random.seed(42)

    sampled = []
    # Take top 2000 (very popular sites)
    tier1 = domains[:5000]
    sampled.extend(random.sample(tier1, min(max_domains // 3, len(tier1))))

    # Take middle tier (5K-100K)
    tier2 = domains[5000:100000]
    sampled.extend(random.sample(tier2, min(max_domains // 3, len(tier2))))

    # Take lower tier (100K-500K)
    tier3 = domains[100000:500000]
    sampled.extend(random.sample(tier3, min(max_domains // 3, len(tier3))))

    random.shuffle(sampled)
    urls = [f"https://{d}" for d in sampled[:max_domains]]
    print(f"  Sampled {len(urls)} legitimate domains from Tranco")
    return urls


def extract_features_safe(url, timeout_per_url=30):
    """Extract features from a URL with error handling."""
    try:
        features = featureExtraction(url)
        return {'url': url, 'features': features, 'error': None}
    except Exception as e:
        return {'url': url, 'features': None, 'error': str(e)}


def load_checkpoint():
    """Load checkpoint to resume from where we left off."""
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, 'r') as f:
            return json.load(f)
    return {'phishing_done': 0, 'legitimate_done': 0, 'rows': []}


def save_checkpoint(checkpoint):
    """Save checkpoint for resuming."""
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump(checkpoint, f)


def process_urls(urls, label, label_name, checkpoint, max_workers=MAX_WORKERS):
    """Extract features from a list of URLs with progress tracking."""
    key = f'{label_name}_done'
    start_idx = checkpoint.get(key, 0)

    if start_idx >= len(urls):
        print(f"  {label_name} features already extracted ({start_idx} done)")
        return

    remaining = urls[start_idx:]
    print(f"  Extracting features for {len(remaining)} {label_name} URLs "
          f"(starting from #{start_idx})...")

    completed = 0
    errors = 0

    # Process in batches to allow checkpointing
    batch_size = 50
    for batch_start in range(0, len(remaining), batch_size):
        batch = remaining[batch_start:batch_start + batch_size]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(extract_features_safe, url): url for url in batch}

            for future in as_completed(futures):
                result = future.result()
                if result['features'] is not None:
                    row = result['features'] + [label]
                    checkpoint['rows'].append(row)
                    completed += 1
                else:
                    errors += 1

        # Update checkpoint
        checkpoint[key] = start_idx + batch_start + len(batch)
        save_checkpoint(checkpoint)

        total_done = completed + errors
        if total_done % 100 == 0 or total_done == len(remaining):
            print(f"    Progress: {total_done}/{len(remaining)} "
                  f"({completed} success, {errors} errors)")

        # Small delay between batches to be kind to external services
        time.sleep(WHOIS_DELAY)

    print(f"  {label_name} done: {completed} success, {errors} errors")


def build_dataset(max_samples=5000, resume=False):
    """Main dataset building function."""
    os.makedirs(DATASET_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

    print("=" * 60)
    print("PhishGuard Dataset Builder")
    print(f"Target: {max_samples} samples per class ({max_samples * 2} total)")
    print(f"Features: {TOTAL_FEATURES}")
    print(f"Output: {OUTPUT_FILE}")
    print("=" * 60)

    # Load checkpoint if resuming
    if resume:
        checkpoint = load_checkpoint()
        print(f"Resuming from checkpoint: {checkpoint.get('phishing_done', 0)} phishing, "
              f"{checkpoint.get('legitimate_done', 0)} legitimate done")
    else:
        checkpoint = {'phishing_done': 0, 'legitimate_done': 0, 'rows': []}

    # Step 1: Download URLs
    print("\n[1/4] Downloading phishing URLs...")
    phishing_urls = download_phishtank_urls(max_urls=max_samples)

    print("\n[2/4] Downloading legitimate domains...")
    legitimate_urls = download_tranco_domains(max_domains=max_samples)

    if not phishing_urls:
        print("ERROR: No phishing URLs available. Cannot build dataset.")
        return False

    if not legitimate_urls:
        print("ERROR: No legitimate URLs available. Cannot build dataset.")
        return False

    # Step 2: Extract features
    print(f"\n[3/4] Extracting features ({TOTAL_FEATURES} per URL)...")
    print("  This will take a while due to WHOIS lookups and HTTP requests.")
    print(f"  Using {MAX_WORKERS} parallel workers.\n")

    process_urls(phishing_urls, label=1, label_name='phishing', checkpoint=checkpoint)
    process_urls(legitimate_urls, label=0, label_name='legitimate', checkpoint=checkpoint)

    # Step 3: Write CSV
    print(f"\n[4/4] Writing dataset to {OUTPUT_FILE}...")
    header = FEATURE_NAMES + ['label']

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for row in checkpoint['rows']:
            if len(row) == TOTAL_FEATURES + 1:  # features + label
                writer.writerow(row)

    total_rows = len([r for r in checkpoint['rows'] if len(r) == TOTAL_FEATURES + 1])
    phishing_count = sum(1 for r in checkpoint['rows'] if len(r) == TOTAL_FEATURES + 1 and r[-1] == 1)
    legit_count = total_rows - phishing_count

    print(f"\nDataset built successfully!")
    print(f"  Total samples: {total_rows}")
    print(f"  Phishing: {phishing_count}")
    print(f"  Legitimate: {legit_count}")
    print(f"  Features: {TOTAL_FEATURES}")
    print(f"  File: {OUTPUT_FILE}")

    # Clean up checkpoint
    if os.path.exists(CHECKPOINT_FILE):
        os.remove(CHECKPOINT_FILE)

    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Build phishing URL detection dataset')
    parser.add_argument('--samples', type=int, default=5000,
                        help='Max samples per class (default: 5000)')
    parser.add_argument('--resume', action='store_true',
                        help='Resume from checkpoint')
    parser.add_argument('--workers', type=int, default=MAX_WORKERS,
                        help=f'Number of parallel workers (default: {MAX_WORKERS})')
    args = parser.parse_args()

    MAX_WORKERS = args.workers
    build_dataset(max_samples=args.samples, resume=args.resume)
