import threading
import time
import logging
from datetime import datetime, timedelta
import requests
import os
import sqlite3
from urllib.parse import urlparse

from .reputation_check import update_phishing_database
from .feature import load_tranco_list

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("phishing_updater.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PhishingDBUpdater")

class DatabaseUpdaterThread(threading.Thread):
    """Background thread to update phishing database periodically"""
    
    def __init__(self, update_interval=86400):  # Default: 24 hours
        super().__init__()
        self.daemon = True  # Daemon thread will automatically close when main thread ends
        self.update_interval = update_interval
        self.should_stop = threading.Event()
        
    def run(self):
        """Run the background task"""
        logger.info("Starting database updater thread")
        
        # First update immediately
        self._update_database()
        
        # Then update periodically
        while not self.should_stop.is_set():
            # Sleep for the interval, but check for stop signal every minute
            for _ in range(int(self.update_interval / 60)):
                if self.should_stop.is_set():
                    break
                time.sleep(60)
                
            if not self.should_stop.is_set():
                self._update_database()
        
        logger.info("Database updater thread stopped")
    
    def _update_database(self):
        """Run the database update with error handling"""
        try:
            logger.info("Starting phishing database update")
            update_phishing_database()
            logger.info("Database update completed")
        except Exception as e:
            logger.error(f"Error in database updater: {str(e)}")

        # Update Tranco top-1M list
        self._update_tranco_list()

    def _update_tranco_list(self):
        """Download and cache the Tranco top-1M domain list."""
        cache_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                 'phishingUrlDetectionBackend', 'cache')
        os.makedirs(cache_dir, exist_ok=True)
        csv_path = os.path.join(cache_dir, 'tranco_top1m.csv')

        # Only re-download if file is missing or older than 24 hours
        if os.path.exists(csv_path):
            age = time.time() - os.path.getmtime(csv_path)
            if age < 86400:
                logger.info("Tranco list is up to date, loading from cache")
                load_tranco_list(csv_path)
                return

        try:
            logger.info("Downloading Tranco top-1M list...")
            url = 'https://tranco-list.eu/top-1m.csv.zip'
            resp = requests.get(url, timeout=60)
            if resp.status_code == 200:
                import zipfile, io
                with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                    # The zip contains a single CSV file
                    names = zf.namelist()
                    with zf.open(names[0]) as src, open(csv_path, 'wb') as dst:
                        dst.write(src.read())
                logger.info("Tranco list downloaded successfully")
                load_tranco_list(csv_path)
            else:
                logger.error(f"Tranco download failed: HTTP {resp.status_code}")
                # Still try to load a stale copy if it exists
                if os.path.exists(csv_path):
                    load_tranco_list(csv_path)
        except Exception as e:
            logger.error(f"Error updating Tranco list: {e}")
            if os.path.exists(csv_path):
                load_tranco_list(csv_path)
    
    def stop(self):
        """Stop the thread"""
        self.should_stop.set()

class ModelRetrainerThread(threading.Thread):
    """Background thread to retrain the ML model periodically (weekly)."""

    def __init__(self, interval=7 * 86400):  # Default: 7 days
        super().__init__()
        self.daemon = True
        self.interval = interval
        self.should_stop = threading.Event()

    def run(self):
        logger.info("Model retrainer thread started (interval: %d seconds)", self.interval)
        # Wait for the first interval before retraining
        for _ in range(int(self.interval / 60)):
            if self.should_stop.is_set():
                return
            time.sleep(60)

        while not self.should_stop.is_set():
            self._retrain()
            for _ in range(int(self.interval / 60)):
                if self.should_stop.is_set():
                    break
                time.sleep(60)

    def _retrain(self):
        try:
            logger.info("Starting scheduled model retraining...")
            from django.core.management import call_command
            call_command('retrain_model', '--quick', '--include-feedback')
            logger.info("Scheduled model retraining completed")
        except Exception as e:
            logger.error(f"Model retraining failed: {e}")

    def stop(self):
        self.should_stop.set()


# Global thread instances
updater_thread = None
retrainer_thread = None

def start_database_updater():
    """Start the background database updater thread"""
    global updater_thread

    if updater_thread is None or not updater_thread.is_alive():
        updater_thread = DatabaseUpdaterThread()
        updater_thread.start()
        logger.info("Database updater thread started")
    else:
        logger.info("Database updater thread already running")


def start_model_retrainer():
    """Start the background model retrainer thread (weekly)."""
    global retrainer_thread

    if retrainer_thread is None or not retrainer_thread.is_alive():
        retrainer_thread = ModelRetrainerThread()
        retrainer_thread.start()
        logger.info("Model retrainer thread started")
    else:
        logger.info("Model retrainer thread already running")


