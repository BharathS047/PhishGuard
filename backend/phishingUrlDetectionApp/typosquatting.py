"""
Typosquatting detection module for the phishing URL detection app.
This module provides functions to detect typosquatting domains using Levenshtein distance.
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional


def levenshtein_distance(str1: str, str2: str) -> int:
    """
    Calculate the Levenshtein distance between two strings.
    
    Args:
        str1: First string
        str2: Second string
        
    Returns:
        The Levenshtein distance between the strings
    """
    # Create a matrix of size (len(str1) + 1) x (len(str2) + 1)
    dp = [[0 for _ in range(len(str2) + 1)] for _ in range(len(str1) + 1)]
    
    # Initialize the first row and column
    for i in range(len(str1) + 1):
        dp[i][0] = i
    for j in range(len(str2) + 1):
        dp[0][j] = j
    
    # Fill the matrix
    for i in range(1, len(str1) + 1):
        for j in range(1, len(str2) + 1):
            cost = 0 if str1[i-1] == str2[j-1] else 1
            dp[i][j] = min(
                dp[i-1][j] + 1,  # deletion
                dp[i][j-1] + 1,  # insertion
                dp[i-1][j-1] + cost  # substitution
            )
    
    return dp[len(str1)][len(str2)]


def domain_similarity_ratio(domain1: str, domain2: str) -> float:
    """
    Calculate how similar two domain names are as a ratio.
    
    Args:
        domain1: First domain name
        domain2: Second domain name
        
    Returns:
        A similarity score between 0 and 1 (1 means identical)
    """
    # Remove TLD for better comparison
    domain1_base = domain1.split('.')[0] if '.' in domain1 else domain1
    domain2_base = domain2.split('.')[0] if '.' in domain2 else domain2
    
    # Get Levenshtein distance
    distance = levenshtein_distance(domain1_base, domain2_base)
    
    # Calculate similarity ratio
    max_len = max(len(domain1_base), len(domain2_base))
    if max_len == 0:
        return 0
    
    return 1 - (distance / max_len)


def check_typosquatting(domain: str, known_domains: List[str], threshold: float = 0.8) -> Optional[Dict]:
    """
    Check if a domain might be typosquatting a known domain.
    
    Args:
        domain: The domain to check
        known_domains: List of known domains to compare against
        threshold: Similarity threshold (0-1) to consider as typosquatting
        
    Returns:
        None if no match found, or a dict with matched domain and similarity score
    """
    # Standard preprocessing
    domain = domain.lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    
    best_match = None
    highest_similarity = 0
    
    # Check similarity against each known domain
    for known_domain in known_domains:
        known_domain = known_domain.lower()
        if known_domain.startswith('www.'):
            known_domain = known_domain[4:]
        
        # Skip exact matches (these would be handled by trusted domains check)
        if domain == known_domain:
            continue
        
        similarity = domain_similarity_ratio(domain, known_domain)
        if similarity > highest_similarity:
            highest_similarity = similarity
            best_match = known_domain
    
    if highest_similarity >= threshold:
        return {
            'is_typosquatting': True,
            'impersonated_domain': best_match,
            'similarity': highest_similarity,
            'confidence': highest_similarity * 0.9  # Scale confidence by similarity
        }
    
    return None


def extract_domain_from_url(url: str) -> str:
    """
    Extract domain from a URL.
    
    Args:
        url: The URL to extract domain from
        
    Returns:
        The domain part of the URL
    """
    try:
        # Remove @ symbol before parsing if present
        url = url.replace('@', '')
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Strip 'www.' if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain
    except Exception:
        # If parsing fails, return empty string
        return ""


def check_homograph_attack(domain: str) -> bool:
    """
    Check if a domain might be using homograph attack (using similar-looking Unicode characters).
    
    Args:
        domain: The domain to check
        
    Returns:
        True if homograph attack is detected, False otherwise
    """
    # Check for non-ASCII characters in domain
    return any(ord(c) > 127 for c in domain) 