import re
import base64
import email
from email import policy
from email.parser import Parser
from urllib.parse import urlparse
import json


# ── Utility: lightweight edit-distance for fuzzy domain matching ──────────

def _levenshtein(a: str, b: str) -> int:
    """Calculate the Levenshtein (edit) distance between two strings."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        cur_row = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            cur_row.append(min(cur_row[j] + 1, prev_row[j + 1] + 1, prev_row[j] + cost))
        prev_row = cur_row
    return prev_row[-1]


# Well-known domains used for fuzzy / lookalike matching
KNOWN_DOMAINS = {
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'live.com',
    'google.com', 'microsoft.com', 'amazon.com', 'paypal.com',
    'facebook.com', 'apple.com', 'netflix.com', 'instagram.com',
    'twitter.com', 'linkedin.com', 'dropbox.com', 'icloud.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
    'americanexpress.com', 'dhl.com', 'fedex.com', 'ups.com',
    'spotify.com', 'adobe.com', 'zoom.us', 'slack.com', 'github.com',
}


def _is_lookalike_domain(domain: str, threshold: int = 2) -> tuple:
    """Check if *domain* is within *threshold* edits of any known domain.

    Returns (True, matched_brand) or (False, None).
    """
    domain = domain.lower().strip()
    if domain in KNOWN_DOMAINS:
        return (False, None)  # exact match → not a lookalike

    for known in KNOWN_DOMAINS:
        dist = _levenshtein(domain, known)
        if 0 < dist <= threshold:
            brand = known.split('.')[0]
            return (True, brand)
    return (False, None)


# ── EmailHeaderAnalyzer ───────────────────────────────────────────────────

class EmailHeaderAnalyzer:
    """Analyzes email headers for phishing indicators"""
    
    def __init__(self):
        self.suspicious_indicators = []
        self.authentication_results = {}
        self.routing_info = []
        self.parsed_headers = {}
    
    def analyze(self, headers_text, sender='', subject=''):
        """Main analysis function for email headers.

        If *headers_text* is empty but *sender* / *subject* are provided,
        synthetic minimal headers are constructed so that header-level
        checks (Reply-To mismatch, etc.) still fire.
        """
        self.suspicious_indicators = []
        self.authentication_results = {}
        self.routing_info = []

        # Build synthetic headers when user didn't paste raw headers
        if not headers_text.strip() and (sender or subject):
            headers_text = f"From: {sender}\r\nSubject: {subject}\r\n"
        
        # Parse the headers
        headers = Parser(policy=policy.default).parsestr(headers_text)
        
        # Extract key headers
        self.parsed_headers = {
            'from': headers.get('From', ''),
            'to': headers.get('To', ''),
            'subject': headers.get('Subject', ''),
            'date': headers.get('Date', ''),
            'message_id': headers.get('Message-ID', ''),
            'reply_to': headers.get('Reply-To', ''),
            'return_path': headers.get('Return-Path', ''),
            'received': self._parse_received_headers(headers),
            'authentication_results': headers.get('Authentication-Results', ''),
            'dkim_signature': headers.get('DKIM-Signature', ''),
            'spf': '',
            'dkim': '',
            'dmarc': ''
        }
        
        # Check for authentication results
        self._parse_authentication_results()
        
        # Check for indicators of phishing
        self._check_spoofing_indicators()
        self._check_unusual_routing()
        self._check_reply_to_mismatch()
        self._check_sender_domain()
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score()
        
        return {
            'parsed_headers': self.parsed_headers,
            'authentication_results': self.authentication_results,
            'suspicious_indicators': self.suspicious_indicators,
            'routing_info': self.routing_info,
            'risk_score': risk_score,
            'risk_level': self._risk_level_from_score(risk_score)
        }
    
    def _parse_received_headers(self, headers):
        """Extract and parse Received headers"""
        received_headers = headers.get_all('Received', [])
        return received_headers
    
    def _parse_authentication_results(self):
        """Parse SPF, DKIM, and DMARC results from headers"""
        auth_results = self.parsed_headers['authentication_results']
        
        # Parse SPF
        spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        if spf_match:
            self.authentication_results['spf'] = spf_match.group(1).lower()
            self.parsed_headers['spf'] = spf_match.group(1).lower()
        
        # Parse DKIM
        dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
        if dkim_match:
            self.authentication_results['dkim'] = dkim_match.group(1).lower()
            self.parsed_headers['dkim'] = dkim_match.group(1).lower()
        
        # Parse DMARC
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
        if dmarc_match:
            self.authentication_results['dmarc'] = dmarc_match.group(1).lower()
            self.parsed_headers['dmarc'] = dmarc_match.group(1).lower()
    
    def _check_spoofing_indicators(self):
        """Check for indicators of email spoofing"""
        
        # Check SPF
        if 'spf' in self.authentication_results:
            if self.authentication_results['spf'] != 'pass':
                self.suspicious_indicators.append({
                    'type': 'authentication',
                    'name': 'SPF Authentication Failure',
                    'description': 'Email failed SPF authentication, suggesting possible spoofing',
                    'severity': 'high'
                })
        else:
            self.suspicious_indicators.append({
                'type': 'authentication',
                'name': 'Missing SPF Authentication',
                'description': 'No SPF authentication results found',
                'severity': 'medium'
            })
        
        # Check DKIM
        if 'dkim' in self.authentication_results:
            if self.authentication_results['dkim'] != 'pass':
                self.suspicious_indicators.append({
                    'type': 'authentication',
                    'name': 'DKIM Authentication Failure',
                    'description': 'Email failed DKIM authentication, suggesting tampering',
                    'severity': 'high'
                })
        else:
            self.suspicious_indicators.append({
                'type': 'authentication',
                'name': 'Missing DKIM Authentication',
                'description': 'No DKIM authentication results found',
                'severity': 'medium'
            })
        
        # Check DMARC
        if 'dmarc' in self.authentication_results:
            if self.authentication_results['dmarc'] != 'pass':
                self.suspicious_indicators.append({
                    'type': 'authentication',
                    'name': 'DMARC Authentication Failure',
                    'description': 'Email failed DMARC authentication',
                    'severity': 'high'
                })
        else:
            self.suspicious_indicators.append({
                'type': 'authentication',
                'name': 'Missing DMARC Authentication',
                'description': 'No DMARC authentication results found',
                'severity': 'low'
            })
    
    def _check_unusual_routing(self):
        """Check for unusual email routing patterns"""
        received_headers = self.parsed_headers['received']
        
        # Extract IP addresses from Received headers
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        for i, header in enumerate(received_headers):
            ips = re.findall(ip_pattern, header)
            
            # Add to routing info
            if ips:
                self.routing_info.append({
                    'hop': i + 1,
                    'header': header,
                    'ip_addresses': ips
                })
                
        # Check for excessive hops
        if len(received_headers) > 15:
            self.suspicious_indicators.append({
                'type': 'routing',
                'name': 'Excessive Mail Hops',
                'description': f'Email passed through {len(received_headers)} servers, which is unusual',
                'severity': 'medium'
            })
    
    def _check_reply_to_mismatch(self):
        """Check if Reply-To doesn't match From header"""
        from_email = self._extract_email(self.parsed_headers['from'])
        reply_to = self._extract_email(self.parsed_headers['reply_to'])
        return_path = self._extract_email(self.parsed_headers['return_path'])
        
        if reply_to and from_email and reply_to != from_email:
            self.suspicious_indicators.append({
                'type': 'mismatch',
                'name': 'Reply-To/From Mismatch',
                'description': f'Reply-To address ({reply_to}) differs from From address ({from_email})',
                'severity': 'high'
            })
        
        if return_path and from_email and return_path != from_email:
            self.suspicious_indicators.append({
                'type': 'mismatch',
                'name': 'Return-Path/From Mismatch',
                'description': f'Return-Path ({return_path}) differs from From address ({from_email})',
                'severity': 'medium'
            })

    def _check_sender_domain(self):
        """Check sender domain for lookalike / typosquatting."""
        from_addr = self._extract_email(self.parsed_headers['from'])
        if not from_addr or '@' not in from_addr:
            return

        domain = from_addr.split('@')[1].lower()
        is_lookalike, brand = _is_lookalike_domain(domain)
        if is_lookalike:
            self.suspicious_indicators.append({
                'type': 'sender',
                'name': 'Lookalike Sender Domain',
                'description': f'Sender domain "{domain}" is suspiciously similar to {brand} (possible typosquatting)',
                'severity': 'high'
            })
    
    def _extract_email(self, header_value):
        """Extract email address from a header value"""
        if not header_value:
            return ''
            
        # Try to match email pattern
        email_pattern = r'[\w\.-]+@[\w\.-]+'
        match = re.search(email_pattern, header_value)
        
        if match:
            return match.group(0).lower()
        
        return header_value.lower()
    
    def _calculate_risk_score(self):
        """Calculate a risk score based on findings"""
        score = 0
        
        # Authentication failures have high weight
        if 'spf' in self.authentication_results and self.authentication_results['spf'] != 'pass':
            score += 25
        
        if 'dkim' in self.authentication_results and self.authentication_results['dkim'] != 'pass':
            score += 25
            
        if 'dmarc' in self.authentication_results and self.authentication_results['dmarc'] != 'pass':
            score += 15
        
        # Missing authentications
        if 'spf' not in self.authentication_results:
            score += 10
        
        if 'dkim' not in self.authentication_results:
            score += 10
            
        if 'dmarc' not in self.authentication_results:
            score += 5
        
        # Each other suspicious indicator
        for indicator in self.suspicious_indicators:
            if indicator['type'] not in ['authentication']:  # Already counted above
                if indicator['severity'] == 'high':
                    score += 15
                elif indicator['severity'] == 'medium':
                    score += 10
                else:
                    score += 5
        
        # Cap at 100
        return min(score, 100)
    
    def _risk_level_from_score(self, score):
        """Convert numerical score to risk level"""
        if score >= 75:
            return 'High Risk'
        elif score >= 40:
            return 'Medium Risk'
        elif score >= 15:
            return 'Low Risk'
        else:
            return 'Safe'


# ── EmailContentAnalyzer ──────────────────────────────────────────────────

class EmailContentAnalyzer:
    """Analyzes email content for phishing indicators"""
    
    # Expanded keyword / phrase lists
    SUSPICIOUS_TLDS = [
        '.tk', '.pw', '.cf', '.ga', '.gq', '.ml', '.buzz', '.xyz',
        '.top', '.info', '.click', '.link', '.club', '.work', '.icu',
        '.cam', '.rest', '.monster',
    ]

    URGENT_SUBJECT_TERMS = [
        'urgent', 'immediate', 'attention', 'important', 'alert',
        'action required', 'warning', 'critical', 'suspended',
        'verify', 'confirm', 'locked', 'blocked', 'restricted',
        'unusual activity', 'security notice', 'final warning',
        'expiring', 'deadline', 'last chance',
    ]

    FINANCIAL_SUBJECT_TERMS = [
        'account', 'payment', 'invoice', 'transaction', 'bank',
        'credit card', 'paypal', 'deposit', 'tax', 'refund',
        'billing', 'wire transfer', 'overdue', 'statement',
    ]

    PHISHING_BODY_PHRASES = [
        'verify your account', 'confirm your account', 'update your information',
        'update your password', 'login to your account', 'suspicious activity',
        'click here to verify', 'security alert', 'limited time', 'act now',
        'failure to comply', 'your account has been suspended', 'unauthorized access',
        'your account has been locked', 'your account has been blocked',
        'your account has been restricted', 'your account has been compromised',
        'click the link below', 'click on this link', 'click here immediately',
        'verify your identity', 'confirm your identity', 'reset your password',
        'unusual sign-in', 'unusual login', 'sign-in attempt',
        'we detected unusual', 'we noticed unusual', 'we noticed a sign-in',
        'update your details', 'complete your verification',
        'to unlock your account', 'to restore your account',
        'to reactivate your account', 'to avoid suspension',
    ]

    URGENCY_BODY_PHRASES = [
        'immediate action', 'urgent action', 'time sensitive', 'expires soon',
        'final notice', 'last chance', 'deadline', 'suspended', 'terminated',
        'locked', 'disabled', 'deleted', 'criminal', 'illegal', 'unauthorized',
        'blocked', 'restricted', 'compromised', 'breach detected',
        'within 24 hours', 'within 48 hours', 'immediately',
        'failure to respond', 'failure to verify', 'failure to update',
        'your access will be', 'will be permanently',
    ]

    COMMON_SPELLING_ERRORS = [
        'detecte unusual', 'suspicius', 'kindely', 'inconvinience', 'securty',
        'verifcation', 'informations', 'we detected', 'we notice', 'need update',
        'immediatly', 'sucessful', 'recieve', 'accout', 'payemnt', 'transacton',
        'verfy', 'updation', 'loging', 'pasword', 'secuirty', 'registeration',
    ]

    REWARD_PHRASES = [
        'free', 'bonus', 'prize', 'winner', 'discount', 'offer',
        'gift', 'reward', 'congratulations', 'you have won', 'selected',
        'lucky', 'claim your', 'collect your',
    ]

    FEAR_PHRASES = [
        'breach', 'hacked', 'vulnerable', 'at risk', 'compromised',
        'stolen', 'fraud', 'identity theft', 'data leak', 'exposed',
        'malware', 'virus detected',
    ]

    AUTHORITY_PHRASES = [
        'irs', 'internal revenue', 'federal', 'law enforcement',
        'legal action', 'court order', 'subpoena', 'investigation',
        'compliance department', 'security team', 'IT department',
    ]
    
    def __init__(self):
        self.suspicious_indicators = []
        self.extracted_urls = []
        self.social_engineering_tactics = []
    
    def analyze(self, sender, subject, body):
        """Main analysis function for email content"""
        self.suspicious_indicators = []
        self.extracted_urls = []
        self.social_engineering_tactics = []
        
        # Analyze sender domain
        self._analyze_sender(sender)
        
        # Analyze subject line
        self._analyze_subject(subject)
        
        # Analyze email body
        self._analyze_body(body)
        
        # Extract and analyze URLs
        self._extract_urls(body)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score()
        
        return {
            'suspicious_indicators': self.suspicious_indicators,
            'extracted_urls': self.extracted_urls,
            'social_engineering_tactics': self.social_engineering_tactics,
            'risk_score': risk_score,
            'risk_level': self._risk_level_from_score(risk_score)
        }
    
    def _analyze_sender(self, sender):
        """Analyze sender email address for suspicious patterns"""
        if not sender:
            return
            
        # Check for suspicious TLDs
        for tld in self.SUSPICIOUS_TLDS:
            if sender.lower().endswith(tld):
                self.suspicious_indicators.append({
                    'type': 'sender',
                    'name': 'Suspicious Email TLD',
                    'description': f'Sender uses suspicious top-level domain: {tld}',
                    'severity': 'medium'
                })
                break
        
        sender_parts = sender.split('@')
        if len(sender_parts) > 1:
            local_part = sender_parts[0]
            domain = sender_parts[1].lower()
            
            # Random-looking patterns with numbers and letters
            if re.match(r'^[a-z0-9]{10,}$', local_part, re.IGNORECASE):
                self.suspicious_indicators.append({
                    'type': 'sender',
                    'name': 'Suspicious Sender Username',
                    'description': 'Sender username appears random or machine-generated',
                    'severity': 'low'
                })

            # ── Fuzzy / lookalike domain check ──
            is_lookalike, brand = _is_lookalike_domain(domain)
            if is_lookalike:
                self.suspicious_indicators.append({
                    'type': 'sender',
                    'name': 'Lookalike Sender Domain',
                    'description': f'Sender domain "{domain}" is suspiciously similar to {brand} (possible typosquatting)',
                    'severity': 'high'
                })
    
    def _analyze_subject(self, subject):
        """Analyze email subject for phishing indicators"""
        if not subject:
            return
            
        subject_lower = subject.lower()
        
        # Check for urgent language
        for term in self.URGENT_SUBJECT_TERMS:
            if term in subject_lower:
                self.suspicious_indicators.append({
                    'type': 'subject',
                    'name': 'Urgency in Subject',
                    'description': f'Subject contains urgent language: "{term}"',
                    'severity': 'medium'
                })
                self.social_engineering_tactics.append('urgency')
                break
        
        # Check for financial terms
        for term in self.FINANCIAL_SUBJECT_TERMS:
            if term in subject_lower:
                self.suspicious_indicators.append({
                    'type': 'subject',
                    'name': 'Financial Terms in Subject',
                    'description': f'Subject contains financial terms: "{term}"',
                    'severity': 'low'
                })
                break
        
        # Check for excessive punctuation or capitalization
        if re.search(r'[!?]{2,}', subject):
            self.suspicious_indicators.append({
                'type': 'subject',
                'name': 'Excessive Punctuation',
                'description': 'Subject contains excessive punctuation (multiple ! or ?)',
                'severity': 'medium'
            })

        if re.search(r'[A-Z]{5,}', subject):
            self.suspicious_indicators.append({
                'type': 'subject',
                'name': 'Excessive Capitalization',
                'description': 'Subject contains excessive capitalization (shouting)',
                'severity': 'low'
            })

        # Check for ALL CAPS subject
        words = re.findall(r'[a-zA-Z]+', subject)
        if words and all(w.isupper() for w in words if len(w) > 1):
            self.suspicious_indicators.append({
                'type': 'subject',
                'name': 'All-Caps Subject',
                'description': 'Entire subject line is in UPPERCASE — common phishing tactic',
                'severity': 'medium'
            })
    
    def _analyze_body(self, body):
        """Analyze email body for phishing indicators"""
        if not body:
            return
            
        body_lower = body.lower()
        
        # Check for phishing phrases
        matched_phishing = []
        for phrase in self.PHISHING_BODY_PHRASES:
            if phrase in body_lower:
                matched_phishing.append(phrase)
        
        if matched_phishing:
            self.suspicious_indicators.append({
                'type': 'body',
                'name': 'Phishing Phrase Detected',
                'description': f'Email contains suspicious phrase(s): "{matched_phishing[0]}"' +
                               (f' (and {len(matched_phishing)-1} more)' if len(matched_phishing) > 1 else ''),
                'severity': 'high' if len(matched_phishing) >= 2 else 'medium'
            })
        
        # Check for urgency/threat tactics
        matched_urgency = []
        for phrase in self.URGENCY_BODY_PHRASES:
            if phrase in body_lower:
                matched_urgency.append(phrase)

        if matched_urgency:
            if 'urgency' not in self.social_engineering_tactics:
                self.social_engineering_tactics.append('urgency')
            self.suspicious_indicators.append({
                'type': 'body',
                'name': 'Urgency or Threat Tactic',
                'description': f'Email uses urgency or threat: "{matched_urgency[0]}"' +
                               (f' (and {len(matched_urgency)-1} more)' if len(matched_urgency) > 1 else ''),
                'severity': 'high' if len(matched_urgency) >= 2 else 'medium'
            })
        
        # Check for poor grammar and spelling
        for error in self.COMMON_SPELLING_ERRORS:
            if error in body_lower:
                self.suspicious_indicators.append({
                    'type': 'body',
                    'name': 'Grammar/Spelling Errors',
                    'description': 'Email contains grammatical or spelling errors commonly seen in phishing',
                    'severity': 'medium'
                })
                break
        
        # Check for reward / fear / authority tactics
        for phrase in self.REWARD_PHRASES:
            if phrase in body_lower:
                self.social_engineering_tactics.append('reward')
                break
                
        for phrase in self.FEAR_PHRASES:
            if phrase in body_lower:
                self.social_engineering_tactics.append('fear')
                break

        for phrase in self.AUTHORITY_PHRASES:
            if phrase in body_lower:
                self.social_engineering_tactics.append('authority')
                self.suspicious_indicators.append({
                    'type': 'body',
                    'name': 'Authority Impersonation',
                    'description': f'Email references authority figure / organisation: "{phrase}"',
                    'severity': 'medium'
                })
                break

        # Check for pressure to act quickly (specific time references)
        time_pressure = re.search(
            r'within\s+\d+\s*(hour|minute|day|hr|min)', body_lower
        )
        if time_pressure:
            if 'urgency' not in self.social_engineering_tactics:
                self.social_engineering_tactics.append('urgency')
            self.suspicious_indicators.append({
                'type': 'body',
                'name': 'Time Pressure',
                'description': f'Email pressures action within a deadline: "{time_pressure.group(0)}"',
                'severity': 'high'
            })

        # Check for generic greetings (common in phishing)
        generic_greetings = [
            'dear customer', 'dear user', 'dear account holder',
            'dear valued', 'dear sir', 'dear madam', 'dear member',
        ]
        for greeting in generic_greetings:
            if greeting in body_lower:
                self.suspicious_indicators.append({
                    'type': 'body',
                    'name': 'Generic Greeting',
                    'description': f'Email uses an impersonal greeting: "{greeting}"',
                    'severity': 'low'
                })
                break
    
    def _extract_urls(self, body):
        """Extract and analyze URLs from email body"""
        if not body:
            return

        # ── Improved URL extraction ──
        # Catches normal URLs plus common malformed patterns like "http//:domain.com"
        url_pattern = (
            r'https?://[^\s<>"\']+|'          # standard http/https URLs
            r'https?[:/]+[^\s<>"\']+|'         # malformed variants like http//:
            r'www\.[^\s<>"\']+|'               # www. prefixed
            r'[a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}'  # bare domains
        )
        found_urls = re.findall(url_pattern, body)
        
        # Track URL mismatches (text vs href)
        link_text_pattern = r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1[^>]*>(.*?)</a>'
        link_text_matches = re.findall(link_text_pattern, body, re.IGNORECASE | re.DOTALL)
        
        for url in found_urls:
            url_info = {
                'url': url,
                'suspicious': False,
                'reason': ''
            }

            # Detect malformed URL schemes (http//: or http:/ etc.)
            if re.match(r'https?[:/]{2,}', url) and not re.match(r'https?://', url):
                url_info['suspicious'] = True
                url_info['reason'] = 'Malformed URL scheme (obfuscation attempt)'
                self.suspicious_indicators.append({
                    'type': 'url',
                    'name': 'Malformed URL',
                    'description': f'URL has a malformed scheme: "{url[:40]}" — possible evasion attempt',
                    'severity': 'high'
                })
            
            # Normalise URL for further analysis
            clean_url = url
            if not clean_url.startswith(('http://', 'https://')):
                if clean_url.startswith('www.'):
                    clean_url = 'http://' + clean_url
                elif re.match(r'https?[:/]+', clean_url):
                    # Fix malformed scheme
                    clean_url = re.sub(r'^https?[:/]+', 'http://', clean_url)
                else:
                    clean_url = 'http://' + clean_url
            
            try:
                parsed = urlparse(clean_url)
                netloc = parsed.netloc.lower()
                
                # Check for suspicious TLDs
                for tld in self.SUSPICIOUS_TLDS:
                    if netloc.endswith(tld):
                        url_info['suspicious'] = True
                        url_info['reason'] = f'Suspicious TLD: {tld}'
                        self.suspicious_indicators.append({
                            'type': 'url',
                            'name': 'Suspicious URL TLD',
                            'description': f'Email contains URL with suspicious TLD: {tld}',
                            'severity': 'high'
                        })
                        break
                
                # Check for IP addresses in URLs
                if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', netloc):
                    url_info['suspicious'] = True
                    url_info['reason'] = 'IP address in URL'
                    self.suspicious_indicators.append({
                        'type': 'url',
                        'name': 'IP Address URL',
                        'description': 'Email contains URL with IP address instead of domain name',
                        'severity': 'high'
                    })
                
                # Check for URL redirects via @
                if '@' in netloc:
                    url_info['suspicious'] = True
                    url_info['reason'] = 'URL contains @ symbol (possible redirection)'
                    self.suspicious_indicators.append({
                        'type': 'url',
                        'name': 'URL Redirection',
                        'description': 'URL uses @ symbol for redirection',
                        'severity': 'high'
                    })
                
                # Check for unusual number of subdomains
                subdomain_count = len(netloc.split('.')) - 2
                if subdomain_count > 3:
                    url_info['suspicious'] = True 
                    url_info['reason'] = f'Unusual number of subdomains ({subdomain_count})'
                    self.suspicious_indicators.append({
                        'type': 'url',
                        'name': 'Excessive Subdomains',
                        'description': f'URL contains {subdomain_count} subdomains',
                        'severity': 'medium'
                    })

                # ── Fuzzy domain matching for URLs ──
                if netloc and '.' in netloc:
                    is_lookalike, brand = _is_lookalike_domain(netloc)
                    if is_lookalike:
                        url_info['suspicious'] = True
                        url_info['reason'] = f'Lookalike domain (mimics {brand})'
                        self.suspicious_indicators.append({
                            'type': 'url',
                            'name': 'Lookalike URL Domain',
                            'description': f'URL domain "{netloc}" is suspiciously similar to {brand} (possible typosquatting)',
                            'severity': 'high'
                        })
                
                self.extracted_urls.append(url_info)
                
            except Exception:
                # Invalid URL, but still track it
                url_info['suspicious'] = True
                url_info['reason'] = 'Invalid URL format'
                self.extracted_urls.append(url_info)
        
        # Look for URL text mismatches
        for href, url, text in link_text_matches:
            if text and url and text.strip() != url.strip() and text.strip() not in url.strip():
                existing = [u for u in self.extracted_urls if u['url'] == url]
                if existing:
                    existing[0]['suspicious'] = True
                    existing[0]['reason'] += f' URL text mismatch (displays as: {text.strip()})'
                else:
                    self.extracted_urls.append({
                        'url': url,
                        'suspicious': True,
                        'reason': f'URL text mismatch (displays as: {text.strip()})'
                    })
                
                self.suspicious_indicators.append({
                    'type': 'url',
                    'name': 'URL Text Mismatch',
                    'description': f'Link text "{text.strip()}" doesn\'t match the actual URL',
                    'severity': 'high'
                })
    
    def _calculate_risk_score(self):
        """Calculate a risk score based on findings"""
        score = 0
        
        # URL indicators have high weight
        url_indicators = [i for i in self.suspicious_indicators if i['type'] == 'url']
        for indicator in url_indicators:
            if indicator['severity'] == 'high':
                score += 20
            elif indicator['severity'] == 'medium':
                score += 12
            else:
                score += 5
        
        # Body indicators
        body_indicators = [i for i in self.suspicious_indicators if i['type'] == 'body']
        for indicator in body_indicators:
            if indicator['severity'] == 'high':
                score += 18
            elif indicator['severity'] == 'medium':
                score += 10
            else:
                score += 5
        
        # Subject indicators
        subject_indicators = [i for i in self.suspicious_indicators if i['type'] == 'subject']
        for indicator in subject_indicators:
            if indicator['severity'] == 'high':
                score += 15
            elif indicator['severity'] == 'medium':
                score += 10
            else:
                score += 5
        
        # Sender indicators
        sender_indicators = [i for i in self.suspicious_indicators if i['type'] == 'sender']
        for indicator in sender_indicators:
            if indicator['severity'] == 'high':
                score += 20
            elif indicator['severity'] == 'medium':
                score += 10
            else:
                score += 5
        
        # Social engineering tactics compound the risk
        score += len(self.social_engineering_tactics) * 8
        
        # Multiple tactic types is a strong signal — bonus
        if len(self.social_engineering_tactics) >= 2:
            score += 10
        
        # Cap at 100
        return min(score, 100)
    
    def _risk_level_from_score(self, score):
        """Convert numerical score to risk level"""
        if score >= 75:
            return 'High Risk'
        elif score >= 40:
            return 'Medium Risk'
        elif score >= 15:
            return 'Low Risk'
        else:
            return 'Safe'


# ── Module-level singletons & convenience functions ───────────────────────

header_analyzer = EmailHeaderAnalyzer()
content_analyzer = EmailContentAnalyzer()

def analyze_email_headers(headers_text, sender='', subject=''):
    """Analyze email headers for phishing indicators"""
    return header_analyzer.analyze(headers_text, sender=sender, subject=subject)

def analyze_email_content(sender, subject, body):
    """Analyze email content for phishing indicators"""
    return content_analyzer.analyze(sender, subject, body)