"""
External APIs integration module for the phishing URL detection app.
This module provides functions to check URLs against VirusTotal.
"""

import os
import base64
import requests
from typing import Dict, Any
from urllib.parse import urlparse


class ExternalApiChecker:
    def __init__(self):
        """Initialize the external API checker with API keys from environment variables."""
        self.virustotal_api_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    
    def check_virustotal(self, url: str) -> Dict[str, Any]:
        """
        Check a URL against VirusTotal.
        
        Args:
            url: The URL to check
            
        Returns:
            Dict with results including is_phishing boolean and confidence score
        """
        if not self.virustotal_api_key:
            return {'status': 'error', 'message': 'VirusTotal API key not configured'}
        
        try:
            headers = {
                "x-apikey": self.virustotal_api_key
            }
            
            # URL ID must be base64 encoded and URL safe
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if "data" in data and "attributes" in data["data"]:
                    attributes = data["data"]["attributes"]
                    last_analysis_stats = attributes.get("last_analysis_stats", {})
                    
                    # Count security vendors that flagged as malicious
                    malicious_count = last_analysis_stats.get("malicious", 0)
                    suspicious_count = last_analysis_stats.get("suspicious", 0)
                    total_engines = sum(last_analysis_stats.values())
                    
                    if total_engines == 0:
                        return {'status': 'error', 'message': 'No scan results available'}
                    
                    # Calculate risk percentage
                    risk_percent = ((malicious_count + suspicious_count) / total_engines) * 100
                    
                    return {
                        'status': 'success',
                        'is_phishing': risk_percent >= 5,  # Consider phishing if 5% or more engines flag it
                        'confidence': min(risk_percent / 10, 0.95),  # Normalize to max 0.95 confidence
                        'malicious_detections': malicious_count,
                        'suspicious_detections': suspicious_count,
                        'total_engines': total_engines,
                        'source': 'virustotal'
                    }
                
            # Handle URL not found in VirusTotal
            if response.status_code == 404:
                # Submit for scanning
                scan_url = "https://www.virustotal.com/api/v3/urls"
                payload = {"url": url}
                scan_response = requests.post(scan_url, headers=headers, data=payload, timeout=10)
                
                if scan_response.status_code == 200:
                    return {
                        'status': 'pending',
                        'message': 'URL submitted for scanning',
                        'source': 'virustotal'
                    }
            
            return {'status': 'error', 'message': f"Error: {response.status_code}"}
            
        except Exception as e:
            return {'status': 'error', 'message': f"Exception: {str(e)}"}

    def check_all_apis(self, url: str) -> Dict[str, Any]:
        """
        Check a URL against all configured external APIs.
        
        Args:
            url: The URL to check
            
        Returns:
            Dict with combined results and the most definitive result
        """
        # Check VirusTotal if configured
        if self.virustotal_api_key:
            vt_result = self.check_virustotal(url)
            
            if vt_result.get('status') == 'success':
                return {
                    'is_phishing': vt_result.get('is_phishing', False),
                    'confidence': vt_result.get('confidence', 0),
                    'source': 'virustotal',
                    'details': {'virustotal': vt_result}
                }
        
        return {'status': 'error', 'message': 'No API results available'}


# Create a singleton instance
external_api_checker = ExternalApiChecker()

def check_url_with_external_apis(url: str) -> Dict[str, Any]:
    """
    Check a URL against all configured external APIs.
    
    Args:
        url: The URL to check
        
    Returns:
        Dict with combined results
    """
    return external_api_checker.check_all_apis(url) 