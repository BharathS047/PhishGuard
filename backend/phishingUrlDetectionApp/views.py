import numpy as np
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view
from urllib.parse import urlparse

from .apps import *
from .feature import featureExtraction
from .reputation_check import check_url_reputation, reputation_checker
from .tasks import start_database_updater
from .email_analysis import analyze_email_headers, analyze_email_content
from .models import ScanResult

# Start the database updater thread when Django starts
start_database_updater()

class Home(APIView):
     def get(self, request):
         response_dict = {"home":"api/?url=(enter the url)"}
         print(response_dict)
         return Response(response_dict, status=200)

class Prediction(APIView):
     def get(self, request):
         url_features=[]
         feature_names = ['having_ip_address', 'long_url', 'shortening_service', 'having_@_symbol', 'redirection_//_symbol', 'prefix_suffix_seperation', 'sub_domains', 'https_token', 'age_of_domain', 'dns_record', 'web_traffic', 'domain_registration_length', 'statistical_report', 'iframe', 'mouse_over']
         url = request.GET.get('url')
         
         # EMERGENCY OVERRIDE: Directly whitelist major domains to prevent false positives
         # This is a critical safeguard to ensure major legitimate domains are NEVER flagged as phishing
         try:
             clean_url = url.replace('@', '').lower()
             parsed_url = urlparse(clean_url)
             domain = parsed_url.netloc.lower()
             
             # Strip 'www.' if present
             if domain.startswith('www.'):
                 domain = domain[4:]
             
             # Absolute whitelist - these domains should NEVER be flagged as phishing
             major_trusted_domains = [
                 'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
                 'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
                 'github.com', 'yahoo.com', 'gmail.com', 'hotmail.com', 'outlook.com'
             ]
             
             # Check if domain is in major trusted list or is a subdomain of a trusted domain
             is_major_trusted = False
             for trusted in major_trusted_domains:
                 if domain == trusted or domain.endswith('.' + trusted):
                     is_major_trusted = True
                     break
             
             if is_major_trusted:
                 print(f"EMERGENCY OVERRIDE: Trusted domain detected: {domain}")
                 # Force legitimate result with highest confidence
                 try:
                     res_temp = np.array(featureExtraction(url))
                     res_temp_list = res_temp.tolist()
                 except Exception as e:
                     print(f"Warning: Could not extract features: {e}")
                     res_temp_list = [0] * 15
                 
                 response_dict = {
                     "url": url,
                     "featureExtractionResult": res_temp_list,
                     "predictionMade": 0,  # 0 means legitimate
                     "successRate": 99.9,  # Highest possible confidence
                     "phishRate": 0.1,     # Lowest possible risk
                     "detectionSource": 'emergency_trusted_override'
                 }
                 print(response_dict)
                 ScanResult.objects.create(scan_type='url', target=url, result='legitimate', risk_score=0.1, detection_source='emergency_trusted_override')
                 return Response(response_dict, status=200)
         except Exception as e:
             print(f"Error in emergency override check: {e}")
         
         # Extract domain from URL for trust check first
         is_trusted = False
         domain = ""
         try:
             # Remove @ symbol before parsing if present
             clean_url = url.replace('@', '')
             parsed_url = urlparse(clean_url)
             domain = parsed_url.netloc.lower()
             
             # Strip 'www.' if present
             if domain.startswith('www.'):
                 domain = domain[4:]
                 
             print(f"Processing domain: {domain}")
         except Exception as e:
             print(f"Error parsing domain: {e}")
         
         # First check if this is a trusted domain
         try:
             
             # Direct check against trusted domains
             if reputation_checker._is_trusted_domain(domain):
                 print(f"Domain {domain} is in trusted list!")
                 
                 # Extract URL features for informational purposes
                 try:
                     res_temp = np.array(featureExtraction(url))
                     res_temp_list = res_temp.tolist()
                 except Exception as e:
                     print(f"Warning: Could not extract features: {e}")
                     res_temp_list = [0] * 15
                 
                 response_dict = {
                     "url": url,
                     "featureExtractionResult": res_temp_list,
                     "predictionMade": 0,  # 0 means legitimate
                     "successRate": 98.0,  # Very high confidence for trusted domains
                     "phishRate": 2.0,
                     "detectionSource": 'trusted_list'
                 }
                 print(response_dict)
                 return Response(response_dict, status=200)
         except Exception as e:
             print(f"Error checking trusted domain: {e}")
         
         # Then check with external reputation services and cached data
         reputation_result = check_url_reputation(url)
         
         if reputation_result:
             # We have a definitive result from external reputation services
             is_phishing = reputation_result['is_phishing']
             reputation_source = reputation_result['source']
             confidence = reputation_result.get('confidence', 0.9)
             
             print(f"URL reputation from {reputation_source}: {'Phishing' if is_phishing else 'Legitimate'} (confidence: {confidence})")
             
             # Extract URL features anyway for informational purposes
             try:
                 res_temp = np.array(featureExtraction(url))
                 res_temp_list = res_temp.tolist()
             except Exception as e:
                 print(f"Warning: Could not extract features: {e}")
                 res_temp_list = [0] * 15
             
             # Count how many features flagged suspicious (value == 1)
             suspicious_feature_count = sum(1 for v in res_temp_list if v == 1)
             
             # When reputation says "not phishing" but features disagree,
             # adjust confidence — features are a strong local signal.
             if not is_phishing and suspicious_feature_count >= 3:
                 # 3+ suspicious features override reputation completely
                 is_phishing = True
                 confidence = min(0.5 + suspicious_feature_count * 0.08, 0.95)
                 reputation_source = f"{reputation_source}+features"
                 print(f"OVERRIDE: {suspicious_feature_count} suspicious features overrode reputation verdict")
             elif not is_phishing and suspicious_feature_count >= 1:
                 # 1-2 features reduce confidence in the "safe" verdict
                 confidence = max(confidence - suspicious_feature_count * 0.12, 0.55)
             
             # Calculate confidence rates based on (possibly adjusted) result
             if is_phishing:
                 PredictionMade = 1  # 1 means phishing
                 url_success_rate = round((1 - confidence) * 100, 2)
                 url_phished_rate = round(confidence * 100, 2)
             else:
                 PredictionMade = 0  # 0 means legitimate
                 url_success_rate = round(confidence * 100, 2)
                 url_phished_rate = round((1 - confidence) * 100, 2)
             
             ScanResult.objects.create(scan_type='url', target=url, result='phishing' if is_phishing else 'legitimate', risk_score=url_phished_rate if is_phishing else url_success_rate, detection_source=reputation_source)
             response_dict = {
                 "url": url,
                 "featureExtractionResult": res_temp_list,
                 "predictionMade": PredictionMade,
                 "successRate": url_success_rate,
                 "phishRate": url_phished_rate,
                 "detectionSource": reputation_source
             }
             print(response_dict)
             return Response(response_dict, status=200)
         
         # If no reputation data, fallback to our ML model
         print("No reputation data available, falling back to ML model...")
         
         # Extract URL features
         try:
             import pandas as pd
             res_temp = np.array(featureExtraction(url))
             url_features.append(res_temp)
             testdata = pd.DataFrame(url_features, columns=feature_names)
             
             # Get model instance
             model = PhishingurldetectionappConfig.model
             
             # Make prediction using model
             PredictionMade = model.predict(testdata)[0]
             detection_source = 'ml_model'
             
             # Get probabilities based on model type
             if hasattr(model, 'predict_proba'):
                 proba = model.predict_proba(testdata)[0]
                 
                 # Ensure there are exactly 2 classes in the probability output
                 if len(proba) == 2:
                     # Adjust confidence for well-known domains 
                     if domain and any(trusted in domain for trusted in ["google", "facebook", "microsoft", "apple", "amazon", "github"]):
                         url_success_rate = 98.0
                         url_phished_rate = 2.0
                         PredictionMade = 0  # Force legitimate for well-known domains
                     else:
                         url_success_rate = round(proba[0] * 100, 2)
                         url_phished_rate = round(proba[1] * 100, 2)
                 else:
                     # Fallback if probabilities don't have the expected format
                     url_success_rate = 75.0 if PredictionMade == 0 else 25.0
                     url_phished_rate = 25.0 if PredictionMade == 0 else 75.0
             else:
                 # If model doesn't support predict_proba
                 url_success_rate = 75.0 if PredictionMade == 0 else 25.0
                 url_phished_rate = 25.0 if PredictionMade == 0 else 75.0
             
             # Convert NumPy types to Python native types for JSON serialization
             res_temp_list = res_temp.tolist()
             PredictionMade = int(PredictionMade)
             
             response_dict = {
                 "url": url,
                 "featureExtractionResult": res_temp_list,
                 "predictionMade": PredictionMade,
                 "successRate": url_success_rate,
                 "phishRate": url_phished_rate,
                 "detectionSource": detection_source
             }
             print(response_dict)
             return Response(response_dict, status=200)
             
         except Exception as e:
             error_message = str(e)
             print(f"Error processing URL: {error_message}")
             
             # Return a safe fallback response
             fallback_features = [0] * 15  # 15 zeros for the 15 features
             
             response_dict = {
                 "url": url,
                 "featureExtractionResult": fallback_features,
                 "predictionMade": 0,  # Default as legitimate
                 "successRate": 80.0,
                 "phishRate": 20.0,
                 "detectionSource": "error_fallback"
             }
             return Response(response_dict, status=200)

@api_view(['POST'])
def analyze_email(request):
    """
    API endpoint to analyze email for phishing indicators
    """
    try:
        # Extract data from request
        headers = request.data.get('headers', '')
        sender = request.data.get('sender', '')
        subject = request.data.get('subject', '')
        body = request.data.get('body', '')
        
        # Analyze headers
        header_analysis = analyze_email_headers(headers, sender=sender, subject=subject)
        
        # Analyze content
        content_analysis = analyze_email_content(sender, subject, body)
        
        # Combine results — content analysis is the primary signal when
        # users don't paste raw email headers, so weight it more heavily.
        # Also use the higher of the two as a floor so a single 100-score
        # analysis can't be dragged below "High Risk" by the other.
        weighted_avg = (header_analysis['risk_score'] * 0.3 + content_analysis['risk_score'] * 0.7)
        combined_risk_score = max(weighted_avg, max(header_analysis['risk_score'], content_analysis['risk_score']) * 0.85)
        combined_risk_score = min(combined_risk_score, 100)
        
        if combined_risk_score >= 75:
            risk_level = 'High Risk'
        elif combined_risk_score >= 40:
            risk_level = 'Medium Risk'
        elif combined_risk_score >= 15:
            risk_level = 'Low Risk'
        else:
            risk_level = 'Safe'
        
        result = {
            'header_analysis': header_analysis,
            'content_analysis': content_analysis,
            'combined_risk_score': combined_risk_score,
            'risk_level': risk_level
        }
        
        # Save email scan result
        email_result = 'phishing' if combined_risk_score >= 75 else ('suspicious' if combined_risk_score >= 40 else 'legitimate')
        ScanResult.objects.create(scan_type='email', target=sender, result=email_result, risk_score=combined_risk_score, detection_source='email_analysis')

        return Response(result)
        
    except Exception as e:
        return Response({'error': str(e)}, status=400)


@api_view(['GET'])
def dashboard_stats(request):
    """Return live dashboard statistics from actual scan history."""
    from django.db.models import Count, Avg
    from django.db.models.functions import TruncDate
    import json

    qs = ScanResult.objects.all()
    total = qs.count()

    # ── Totals ──
    phishing_count = qs.filter(result='phishing').count()
    legitimate_count = qs.filter(result='legitimate').count()
    suspicious_count = qs.filter(result='suspicious').count()
    url_scans = qs.filter(scan_type='url').count()
    email_scans = qs.filter(scan_type='email').count()
    avg_risk = qs.aggregate(avg=Avg('risk_score'))['avg'] or 0

    # ── Recent scans (last 20) ──
    recent = list(
        qs.order_by('-created_at')[:20].values(
            'id', 'scan_type', 'target', 'result', 'risk_score',
            'detection_source', 'created_at'
        )
    )
    # Make datetime JSON-serialisable
    for item in recent:
        item['created_at'] = item['created_at'].isoformat()

    # ── Detection source breakdown ──
    sources = list(
        qs.values('detection_source')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    return Response({
        'total_scans': total,
        'phishing_count': phishing_count,
        'legitimate_count': legitimate_count,
        'suspicious_count': suspicious_count,
        'url_scans': url_scans,
        'email_scans': email_scans,
        'avg_risk_score': round(avg_risk, 1),
        'recent_scans': recent,
        'detection_sources': sources,
    })