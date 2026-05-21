import ipaddress
import os
import whois
from urllib.parse import urlparse
from datetime import datetime
import time
import socket
import re
import requests
import traceback



#1. Using the IP Address
def having_ip_address(url):
  try:
    # First try to extract domain name from URL
    parsed = urlparse(url)
    domain = parsed.netloc
    if not domain:
        domain = url
    
    # Try to convert domain to IP address
    ipaddress.ip_address(domain)
    return 1
  except:
    return 0

#2. Long URL
def long_url(url):
    if len(url) < 75:
        return 0
    elif len(url) <= 100:
        return 1
    return 2

#3. Using URL Shortening Services "TinyURL"
def shortening_service(url):
    match=re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
    if match:
        return 1
    else:
        return 0

#4. URL's having "@" Symbol
def have_at_symbol(url):
    if "@" in url:
        return 1
    return 0  

#5. Redirecting using "//"
def redirection(url):
    # Strip the protocol prefix, then check for // in the remainder
    stripped = re.sub(r'^https?://', '', url)
    if '//' in stripped:
        return 1
    return 0

#6. Adding Prefix or Suffix Separated by (-) to the Domain
def prefix_suffix_seperation(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        if '-' in domain:
            return 1
        return 0
    except:
        return 0
    
#7. Sub Domain and Multi Sub Domains
def sub_domains(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            domain = url

        # Remove port if present
        domain = domain.split(':')[0]

        # Strip www. prefix — it's not a meaningful subdomain
        if domain.startswith('www.'):
            domain = domain[4:]

        dot_count = domain.count('.')
        if dot_count <= 1:
            return 0   # example.com — normal
        elif dot_count == 2:
            return 1   # sub.example.com — mild signal
        return 2       # a.b.example.com — suspicious
    except:
        return 0

#8. The Existence of "HTTPS" Token in the Domain Part of the URL
def https_token(url):
    match = re.search('https://|http://', url)
    if match and match.start(0) == 0:
        url = url[match.end(0):]
    match = re.search('http|https', url)
    if match:
        return 1
    else:
        return 0

#  ── WHOIS cache: one lookup per domain, shared across features ──
_whois_cache = {}

def _get_whois_data(url):
    """Single cached WHOIS lookup per domain."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            domain = url
        domain = domain.split(':')[0].lower()
    except:
        return None

    if domain in _whois_cache:
        return _whois_cache[domain]

    try:
        data = whois.whois(domain)
        _whois_cache[domain] = data
        return data
    except Exception as e:
        print(f"WHOIS lookup error for {domain}: {e}")
        _whois_cache[domain] = None
        return None


#9. Age of Domain
def age_of_domain_sub(domain_data):
    creation_date = domain_data.creation_date
    expiration_date = domain_data.expiration_date
    if expiration_date is None or creation_date is None:
        return 0  # Unknown — neutral, not suspicious
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    try:
        ageofdomain = abs((expiration_date - creation_date).days)
        if (ageofdomain / 30) < 6:
            return 1  # Less than 6 months — suspicious
        return 0
    except:
        return 0

def age_of_domain_main(url):
    data = _get_whois_data(url)
    if data is None:
        return 0  # Error — neutral
    return age_of_domain_sub(data)

#  ── DNS cache: one resolution per domain ──
_dns_cache = {}

def _resolve_domain(url):
    """Single cached DNS resolution per domain. Returns IP string or None."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0].lower()
        if not domain:
            domain = url.split('/')[0].lower()
    except:
        return None

    if domain in _dns_cache:
        return _dns_cache[domain]

    try:
        ip = socket.gethostbyname(domain)
        _dns_cache[domain] = ip
        return ip
    except:
        _dns_cache[domain] = None
        return None

#10.DNS Record — checks if domain actually resolves
def dns_record(url):
    try:
        ip = _resolve_domain(url)
        if ip is None:
            return 1  # Domain does not resolve — suspicious
        return 0  # DNS resolves — normal
    except:
        return 0

# 11. Web traffic (uses Tranco top-1M list)
# The Tranco set is populated by tasks.py on startup / periodic update.
# It maps domain -> rank.  Kept at module level so all calls share it.
_tranco_ranks = {}

def load_tranco_list(path=None):
    """Load Tranco CSV into the module-level _tranco_ranks dict."""
    global _tranco_ranks
    if path is None:
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            'phishingUrlDetectionBackend', 'cache', 'tranco_top1m.csv')
    if not os.path.exists(path):
        return
    try:
        with open(path, 'r', encoding='utf-8') as f:
            ranks = {}
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 2:
                    try:
                        ranks[parts[1].lower()] = int(parts[0])
                    except ValueError:
                        continue
            _tranco_ranks = ranks
        print(f"Tranco list loaded: {len(_tranco_ranks)} domains")
    except Exception as e:
        print(f"Error loading Tranco list: {e}")

def web_traffic(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            domain = url
        domain = domain.split(':')[0].lower()
        if domain.startswith('www.'):
            domain = domain[4:]

        if not _tranco_ranks:
            return 0  # List not loaded — neutral, not suspicious

        rank = _tranco_ranks.get(domain)
        if rank is not None:
            if rank <= 10000:
                return 0   # Top 10K — extremely popular, strong safe signal
            elif rank <= 100000:
                return 0   # Top 100K — very popular, safe signal
            else:
                return 1   # Top 1M but low-ranked — mild signal
        return 2  # Not in top 1M — unknown domain, stronger signal
    except Exception as e:
        print(f"Web traffic error: {e}")
        return 0

#12. Domain Registration Length
def domain_registration_length_sub(domain_data):
    expiration_date = domain_data.expiration_date
    if expiration_date is None:
        return 0  # Unknown — neutral
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]
    try:
        today = datetime.now()
        registration_length = abs((expiration_date - today).days)
        if registration_length / 365 <= 1:
            return 1  # Expiring within 1 year — suspicious
        return 0
    except:
        return 0

def domain_registration_length_main(url):
    data = _get_whois_data(url)
    if data is None:
        return 0  # Error — neutral
    return domain_registration_length_sub(data)

#  ── Live phishing domain set — populated by reputation_check.py ──
_known_phishing_domains = set()

def load_phishing_domains(domains):
    """Called by reputation_check to share its live PhishTank data."""
    global _known_phishing_domains
    _known_phishing_domains = set(domains)

#13.Statistical-Report Based Feature — checks live PhishTank + hardcoded fallback
def statistical_report(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        if not hostname:
            hostname = url

        domain = hostname.split(':')[0].lower()
        if domain.startswith('www.'):
            domain = domain[4:]

        # Check against live PhishTank domains (updated every 6 hours)
        if _known_phishing_domains and domain in _known_phishing_domains:
            return 1

        # Fallback: hardcoded high-confidence phishing domains
        url_match = re.search(r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        if url_match:
            return 1

        # Check resolved IP against known-bad IPs
        try:
            ip_address = _resolve_domain(url)
            if ip_address is None:
                return 0
            ip_match = re.search(r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if ip_match:
                return 1
        except:
            pass
            
        return 0
    except Exception as e:
        print(f"Statistical report error: {e}")
        return 0

#14.iFrame Redirection
def iframe_sub(response):
    try:
        if not response or response == "":
            return 0  # No response — neutral
        text = response.text
        # Detect hidden iframes (common phishing technique)
        if re.search(r'<iframe\b[^>]*(?:style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0))', text, re.IGNORECASE):
            return 1  # Hidden iframe — suspicious
        # Detect frameBorder="0" which is also used to hide iframes
        if re.search(r'<iframe\b[^>]*frameborder\s*=\s*["\']0["\']', text, re.IGNORECASE):
            return 1
        return 0
    except:
        return 0

def iframe_main(url):
    try:
        response = requests.get(url, timeout=5)
        return iframe_sub(response)
    except Exception as e:
        print(f"iFrame error: {e}")
        return 0

#15. Status Bar Customization
def mouse_over_sub(response):
    try:
        if not response or response == "":
            return 0  # No response — neutral
        elif re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0
    except:
        return 0

def mouse_over_main(url):
    try:
        response = requests.get(url, timeout=5)
        return mouse_over_sub(response)
    except Exception as e:
        print(f"Mouse over error: {e}")
        return 0

# ══════════════════════════════════════════════════════════════════════
#  NEW FEATURES (16-25)
# ══════════════════════════════════════════════════════════════════════

import math
import ssl
import certifi

#16. URL entropy — random-looking URLs have high Shannon entropy
def url_entropy(url):
    try:
        # Only measure the path + query portion (after domain)
        parsed = urlparse(url)
        payload = (parsed.path or '') + (parsed.query or '') + (parsed.fragment or '')
        if len(payload) < 2:
            return 0
        freq = {}
        for c in payload:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum((cnt / len(payload)) * math.log2(cnt / len(payload)) for cnt in freq.values())
        if entropy > 4.5:
            return 2  # Very high entropy — suspicious
        elif entropy > 3.5:
            return 1  # Moderately high
        return 0
    except:
        return 0

#17. Digit ratio — phishing URLs tend to have more digits
def digit_ratio(url):
    try:
        if len(url) == 0:
            return 0
        ratio = sum(c.isdigit() for c in url) / len(url)
        if ratio > 0.15:
            return 2
        elif ratio > 0.08:
            return 1
        return 0
    except:
        return 0

#18. Special character count in path
def special_char_count(url):
    try:
        parsed = urlparse(url)
        path = (parsed.path or '') + (parsed.query or '')
        count = sum(1 for c in path if c in '%=&+;@!$')
        if count > 8:
            return 2
        elif count > 4:
            return 1
        return 0
    except:
        return 0

#19. Domain length
def domain_length(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
        length = len(domain)
        if length > 30 or length < 4:
            return 1
        return 0
    except:
        return 0

#20. Path depth — deep nesting is suspicious
def path_depth(url):
    try:
        parsed = urlparse(url)
        segments = [s for s in parsed.path.split('/') if s]
        if len(segments) > 5:
            return 2
        elif len(segments) > 3:
            return 1
        return 0
    except:
        return 0

#21. Suspicious TLD
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.xyz',
                   '.buzz', '.icu', '.click', '.link', '.club', '.work',
                   '.rest', '.cam', '.monster', '.info'}

# Valid TLD characters: letters, digits, hyphens only. Must start/end with alnum.
_VALID_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$')

def tld_suspicious(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0].lower()
        if domain.startswith('www.'):
            domain = domain[4:]

        # Check if domain is structurally invalid (commas, spaces, etc.)
        if not _VALID_DOMAIN_RE.match(domain):
            return 1  # Invalid domain format — suspicious

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return 1
        return 0
    except:
        return 0

#22. Punycode / IDN homograph detection
def punycode_detected(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0].lower()
        if 'xn--' in domain:
            return 1
        # Also check for non-ASCII characters
        if any(ord(c) > 127 for c in domain):
            return 1
        return 0
    except:
        return 0

#23. Brand name in subdomain/path but not in actual domain
_BRAND_KEYWORDS = {'paypal', 'apple', 'google', 'microsoft', 'amazon',
                   'facebook', 'netflix', 'instagram', 'linkedin', 'chase',
                   'wellsfargo', 'bankofamerica', 'dropbox', 'icloud',
                   'twitter', 'yahoo', 'outlook', 'gmail'}

# Common character substitutions used in typosquatting / homograph attacks
_TYPO_MAP = {
    'rn': 'm', 'vv': 'w', 'cl': 'd', 'nn': 'm',
    '0': 'o', '1': 'l', '5': 's', '3': 'e',
}

def _normalize_typosquatting(text):
    """Normalize common typosquatting substitutions so lookalikes match the real brand."""
    result = text.lower()
    # Apply multi-char substitutions first (order matters: 'rn' -> 'm' before single-char)
    for fake, real in sorted(_TYPO_MAP.items(), key=lambda x: -len(x[0])):
        result = result.replace(fake, real)
    # Strip hyphens and dots (attackers insert separators: micro-soft, pay.pal)
    result = result.replace('-', '').replace('.', '')
    return result

def _levenshtein(a, b):
    """Minimal Levenshtein distance (no external dependency)."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]

def contains_brand_name(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0].lower()
        if domain.startswith('www.'):
            domain = domain[4:]

        # Check if domain is structurally valid — if not, any brand mention is suspicious
        domain_is_valid = bool(_VALID_DOMAIN_RE.match(domain))

        # Extract the registrable domain (last two parts)
        parts = domain.split('.')
        main_domain = parts[-2] if len(parts) >= 2 else domain
        # Get the TLD
        tld = parts[-1] if len(parts) >= 2 else ''

        # Check if a brand appears in subdomain or path but NOT in main domain
        path_lower = parsed.path.lower()

        # Normalize main domain for typosquatting detection
        normalized_main = _normalize_typosquatting(main_domain)

        for brand in _BRAND_KEYWORDS:
            # Exact match on the actual registrable domain with valid TLD — legitimate
            if brand == main_domain and domain_is_valid and tld in ('com', 'org', 'net', 'io', 'co', 'us', 'tv'):
                continue

            # 1) Exact substring match in domain or path
            if brand in domain or brand in path_lower:
                if not domain_is_valid or brand != main_domain:
                    return 1

            # 2) Typosquatting: normalized domain matches brand exactly
            if normalized_main == brand and main_domain != brand:
                return 1

            # 3) Edit-distance: catch close misspellings (e.g., "gooogle", "amazom")
            if len(brand) >= 5 and _levenshtein(main_domain, brand) <= 2 and main_domain != brand:
                return 1
            if len(brand) >= 5 and _levenshtein(normalized_main, brand) <= 1 and main_domain != brand:
                return 1

        return 0
    except:
        return 0

#24. SSL certificate check
def cert_check(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            return 1  # No HTTPS at all — suspicious
        hostname = parsed.netloc.split(':')[0]
        port = 443
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    return 0  # Valid certificate
        return 1
    except ssl.SSLCertVerificationError:
        return 1  # Self-signed or invalid cert
    except:
        return 0  # Connection error — neutral

#25. Login keywords in URL path
_LOGIN_KEYWORDS = {'login', 'signin', 'sign-in', 'log-in', 'verify',
                   'account', 'secure', 'authenticate', 'confirm',
                   'password', 'credential', 'webscr', 'update-info'}

def url_has_login_keywords(url):
    try:
        parsed = urlparse(url)
        path_lower = (parsed.path + '?' + (parsed.query or '')).lower()
        for kw in _LOGIN_KEYWORDS:
            if kw in path_lower:
                return 1
        return 0
    except:
        return 0


# ══════════════════════════════════════════════════════════════════════
#  MISSING ATTACK FEATURES (26-29)
# ══════════════════════════════════════════════════════════════════════

import base64 as _b64

#26. Data URI phishing — data:text/html;base64,... encodes full phishing pages
def data_uri_phishing(url):
    try:
        stripped = url.strip().lower()
        if stripped.startswith('data:'):
            if 'text/html' in stripped or 'application/xhtml' in stripped:
                return 2  # HTML data URI — very high risk
            return 1  # Non-HTML data URI — still suspicious
        return 0
    except:
        return 0

#27. Open redirect detection — redirect params pointing to external domains
_REDIRECT_PARAMS = re.compile(
    r'(?:redirect|url|next|return|goto|dest|target|continue|rurl|out|link|forward|ref|callback)$',
    re.IGNORECASE
)

def open_redirect_detection(url):
    try:
        from urllib.parse import parse_qs
        parsed = urlparse(url)
        host_domain = parsed.netloc.split(':')[0].lower()
        if host_domain.startswith('www.'):
            host_domain = host_domain[4:]

        params = parse_qs(parsed.query)
        for key, values in params.items():
            if _REDIRECT_PARAMS.search(key):
                for val in values:
                    # Check if the value looks like a URL with a different domain
                    try:
                        target = urlparse(val if '://' in val else 'http://' + val)
                        target_domain = target.netloc.split(':')[0].lower()
                        if target_domain.startswith('www.'):
                            target_domain = target_domain[4:]
                        if target_domain and target_domain != host_domain:
                            return 1  # External redirect — suspicious
                    except:
                        continue
        return 0
    except:
        return 0

#28. Suspicious query string — base64 blobs, credential keywords, excessive params
_CRED_PARAMS = re.compile(r'(?:pass|pwd|token|auth|key|secret|credential|session|cookie)', re.IGNORECASE)

def suspicious_query_string(url):
    try:
        from urllib.parse import parse_qs
        parsed = urlparse(url)
        query = parsed.query or ''
        if not query:
            return 0

        score = 0
        params = parse_qs(query)

        # Check for credential-related parameter names
        for key in params:
            if _CRED_PARAMS.search(key):
                score += 1

        # Check for long base64-encoded values
        for values in params.values():
            for val in values:
                if len(val) > 50:
                    # Check if it looks like base64
                    if re.match(r'^[A-Za-z0-9+/=]{50,}$', val):
                        score += 1

        # Excessive query complexity
        if len(query) > 500 and len(params) > 5:
            score += 1

        if score >= 2:
            return 2
        elif score >= 1:
            return 1
        return 0
    except:
        return 0

#29. Domain-IP mismatch — domain resolves to suspicious IP ranges
_SUSPICIOUS_IP_PREFIXES = (
    '127.', '0.', '10.', '192.168.', '169.254.',  # Private/loopback used as public
)

def domain_ip_mismatch(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0].lower()
        if not domain:
            return 0

        # Skip if domain is already an IP
        try:
            ipaddress.ip_address(domain)
            return 0  # Already caught by having_ip_address feature
        except ValueError:
            pass

        ip = _resolve_domain(url)
        if ip is None:
            return 0  # Can't resolve — handled by dns_record

        # Check for private/loopback IPs being served as public domains
        for prefix in _SUSPICIOUS_IP_PREFIXES:
            if ip.startswith(prefix):
                return 1

        # Check if domain's TLD suggests a specific country but IP is wildly different
        # (simplified: flag domains pointing to known bulletproof hosting ranges)
        # These are commonly abused cloud/VPS IP ranges
        first_octet = int(ip.split('.')[0])
        if first_octet == 0 or first_octet >= 224:
            return 1  # Multicast/reserved — shouldn't serve websites

        return 0
    except:
        return 0


# ── Total feature count ──
TOTAL_FEATURES = 29

def featureExtraction(url):
    features = []
    try:
        # Address bar based features (1-8)
        features.append(having_ip_address(url))
        features.append(long_url(url))
        features.append(shortening_service(url))
        features.append(have_at_symbol(url))
        features.append(redirection(url))
        features.append(prefix_suffix_seperation(url))
        features.append(sub_domains(url))
        features.append(https_token(url))

        # Domain based features (9-13)
        features.append(age_of_domain_main(url))
        features.append(dns_record(url))
        features.append(web_traffic(url))
        features.append(domain_registration_length_main(url))
        features.append(statistical_report(url))

        # HTML & Javascript based features (14-15)
        features.append(iframe_main(url))
        features.append(mouse_over_main(url))

        # New discriminative features (16-25)
        features.append(url_entropy(url))
        features.append(digit_ratio(url))
        features.append(special_char_count(url))
        features.append(domain_length(url))
        features.append(path_depth(url))
        features.append(tld_suspicious(url))
        features.append(punycode_detected(url))
        features.append(contains_brand_name(url))
        features.append(cert_check(url))
        features.append(url_has_login_keywords(url))

        # Missing attack detection features (26-29)
        features.append(data_uri_phishing(url))
        features.append(open_redirect_detection(url))
        features.append(suspicious_query_string(url))
        features.append(domain_ip_mismatch(url))

        # Ensure all features are present
        if len(features) < TOTAL_FEATURES:
            features.extend([0] * (TOTAL_FEATURES - len(features)))

        return features
    except Exception as e:
        print(f"Feature extraction error: {e}")
        print(traceback.format_exc())
        return [0] * TOTAL_FEATURES

