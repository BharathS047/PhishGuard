import threading
import time
import logging
from datetime import datetime, timedelta
import requests
import os
import sqlite3
from urllib.parse import urlparse

from .reputation_check import update_phishing_database

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
            result = update_phishing_database()
            if result['status'] == 'success':
                logger.info(f"Database update successful: {result['message']}")
            elif result['status'] == 'skipped':
                logger.info(f"Database update skipped: {result['message']}")
            else:
                logger.error(f"Database update failed: {result['message']}")
        except Exception as e:
            logger.error(f"Error in database updater: {str(e)}")
    
    def stop(self):
        """Stop the thread"""
        self.should_stop.set()

# Global updater thread instance
updater_thread = None

def start_database_updater():
    """Start the background database updater thread"""
    global updater_thread
    
    if updater_thread is None or not updater_thread.is_alive():
        updater_thread = DatabaseUpdaterThread()
        updater_thread.start()
        logger.info("Database updater thread started")
    else:
        logger.info("Database updater thread already running")


