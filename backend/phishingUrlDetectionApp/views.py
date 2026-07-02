import os
import secrets
import numpy as np
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics, permissions, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from urllib.parse import urlparse
from django.conf import settings as django_settings
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .azure_email import send_email
from django.db.models import Count, Q, Max
from .serializers import RegisterSerializer, UserSerializer, ForgotPasswordSerializer, ResetPasswordSerializer, VerifyEmailSerializer
from urllib.parse import urlparse

from .apps import *
from .feature import featureExtraction
from .reputation_check import check_url_reputation, reputation_checker
from .tasks import start_database_updater, start_model_retrainer
from .email_analysis import analyze_email_headers, analyze_email_content
from .models import ScanResult, EmailVerificationToken, PasswordResetToken

# Start background threads when Django starts
start_database_updater()
start_model_retrainer()

class Home(APIView):
     def get(self, request):
         response_dict = {"home":"api/?url=(enter the url)"}
         print(response_dict)
         return Response(response_dict, status=200)

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = RegisterSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        # Delete any stale OTP and create a fresh one
        EmailVerificationToken.objects.filter(user=user).delete()
        token_obj = EmailVerificationToken.objects.create(user=user)
        expiry = django_settings.EMAIL_VERIFICATION_EXPIRY_MINUTES
        send_email(
            subject='Your PhishGuard verification code',
            plain_text=(
                f'Hi {user.username},\n\n'
                f'Your email verification code is:\n\n'
                f'    {token_obj.token}\n\n'
                f'Enter this code on the verification page. '
                f'It expires in {expiry} minutes.\n\n'
                f'— PhishGuard'
            ),
            recipient_email=user.email,
        )


class VerifyEmailView(APIView):
    """POST { email, otp } → activates the account."""
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': 'Invalid OTP or email.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token_obj = EmailVerificationToken.objects.get(user=user, token=otp)
        except EmailVerificationToken.DoesNotExist:
            return Response({'detail': 'Invalid or expired OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        if token_obj.is_expired():
            token_obj.delete()
            return Response(
                {'detail': 'OTP has expired. Please request a new one.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.is_active = True
        user.save()
        token_obj.delete()
        return Response({'detail': 'Email verified successfully. You may now log in.'})


class ResendVerificationView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        email = request.data.get('email', '').strip()
        generic_msg = {'detail': 'If an account with that email exists and is unverified, a new OTP has been sent.'}

        if not email:
            return Response({'detail': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(generic_msg)

        if user.is_active:
            return Response(generic_msg)

        EmailVerificationToken.objects.filter(user=user).delete()
        token_obj = EmailVerificationToken.objects.create(user=user)
        expiry = django_settings.EMAIL_VERIFICATION_EXPIRY_MINUTES
        send_email(
            subject='Your PhishGuard verification code',
            plain_text=(
                f'Hi {user.username},\n\n'
                f'Your new email verification code is:\n\n'
                f'    {token_obj.token}\n\n'
                f'Enter this code on the verification page. '
                f'It expires in {expiry} minutes.\n\n'
                f'— PhishGuard'
            ),
            recipient_email=user.email,
        )
        return Response(generic_msg)


class ForgotPasswordView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        generic_msg = {'detail': 'If an account with that email exists, a password reset OTP has been sent.'}

        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            return Response(generic_msg)

        PasswordResetToken.objects.filter(user=user).delete()
        token_obj = PasswordResetToken.objects.create(user=user)
        expiry = django_settings.PASSWORD_RESET_EXPIRY_MINUTES
        send_email(
            subject='Your PhishGuard password reset code',
            plain_text=(
                f'Hi {user.username},\n\n'
                f'Your password reset code is:\n\n'
                f'    {token_obj.token}\n\n'
                f'Enter this code on the reset password page. '
                f'It expires in {expiry} minutes.\n'
                f'If you did not request this, ignore this email.\n\n'
                f'— PhishGuard'
            ),
            recipient_email=user.email,
        )
        return Response(generic_msg)


class ResetPasswordView(APIView):
    """POST { email, otp, new_password, confirm_password } → resets the password."""
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        new_password = serializer.validated_data['new_password']

        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            return Response({'detail': 'Invalid OTP or email.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token_obj = PasswordResetToken.objects.get(user=user, token=otp)
        except PasswordResetToken.DoesNotExist:
            return Response({'detail': 'Invalid or expired OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        if token_obj.is_expired():
            token_obj.delete()
            return Response(
                {'detail': 'OTP has expired. Please request a new one.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_password(new_password, user)
        except ValidationError as e:
            return Response({'detail': e.messages}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        PasswordResetToken.objects.filter(user=user).delete()
        return Response({'detail': 'Password reset successfully. You may now log in.'})


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Same behaviour as SimpleJWT's default, but returns a *precise* error so the
    frontend can tell an unverified account apart from wrong credentials.

    SimpleJWT (via Django's ModelBackend) rejects inactive users during
    authenticate(), so an unverified account and a wrong password both surface
    as the identical "No active account found with the given credentials"
    message. We disambiguate: if the username exists, is inactive, and the
    supplied password is actually correct, it's an unverified-email case.
    """

    def validate(self, attrs):
        try:
            return super().validate(attrs)
        except AuthenticationFailed as exc:
            username = attrs.get(self.username_field)
            password = attrs.get('password')
            user = User.objects.filter(**{self.username_field: username}).first()
            if user and not user.is_active and user.check_password(password):
                # Correct password, but the account was never verified.
                raise AuthenticationFailed(
                    {
                        'detail': 'Account not verified. Please verify your email before logging in.',
                        'code': 'account_not_verified',
                    }
                )
            # Unknown user, or user is active, or wrong password → genuine bad credentials.
            raise exc


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class UserProfileView(generics.RetrieveAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

class AdminUsersView(APIView):
    permission_classes = (permissions.IsAdminUser,)

    def get(self, request):
        users = User.objects.annotate(
            total_scans=Count('scans'),
            phishing_count=Count('scans', filter=Q(scans__result='phishing')),
            legitimate_count=Count('scans', filter=Q(scans__result='legitimate')),
            suspicious_count=Count('scans', filter=Q(scans__result='suspicious')),
            last_scan_date=Max('scans__created_at')
        ).order_by('-date_joined')
        
        user_data = []
        for user in users:
            user_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_staff': user.is_staff,
                'date_joined': user.date_joined,
                'total_scans': user.total_scans,
                'phishing_count': user.phishing_count,
                'legitimate_count': user.legitimate_count,
                'suspicious_count': user.suspicious_count,
                'last_scan_date': user.last_scan_date,
            })
        return Response({'users': user_data})

class Prediction(APIView):
     permission_classes = (permissions.IsAuthenticated,)
     
     def get(self, request):
         import pandas as pd

         feature_names = [
             'having_ip_address', 'long_url', 'shortening_service',
             'having_@_symbol', 'redirection_//_symbol', 'prefix_suffix_seperation',
             'sub_domains', 'https_token', 'age_of_domain', 'dns_record',
             'web_traffic', 'domain_registration_length', 'statistical_report',
             'iframe', 'mouse_over',
             # New features (16-25)
             'url_entropy', 'digit_ratio', 'special_char_count',
             'domain_length', 'path_depth', 'tld_suspicious',
             'punycode_detected', 'contains_brand_name', 'cert_check',
             'url_has_login_keywords',
             # Missing attack features (26-29)
             'data_uri_phishing', 'open_redirect_detection',
             'suspicious_query_string', 'domain_ip_mismatch',
         ]

         # ── Feature weights for override scoring (high-signal features weigh more) ──
         FEATURE_WEIGHTS = {
             'having_ip_address': 3.0,
             'shortening_service': 2.5,
             'having_@_symbol': 2.0,
             'redirection_//_symbol': 1.5,
             'https_token': 2.0,
             'statistical_report': 2.5,
             'long_url': 0.5,
             'prefix_suffix_seperation': 0.5,
             'sub_domains': 0.8,
             'age_of_domain': 1.5,
             'dns_record': 1.0,
             'web_traffic': 0.8,
             'domain_registration_length': 1.0,
             'iframe': 1.5,
             'mouse_over': 1.0,
             # New features
             'url_entropy': 1.0,
             'digit_ratio': 0.8,
             'special_char_count': 0.8,
             'domain_length': 0.5,
             'path_depth': 0.5,
             'tld_suspicious': 3.0,
             'punycode_detected': 3.0,
             'contains_brand_name': 3.0,
             'cert_check': 2.0,
             'url_has_login_keywords': 1.5,
             # Missing attack features
             'data_uri_phishing': 3.0,
             'open_redirect_detection': 2.0,
             'suspicious_query_string': 1.5,
             'domain_ip_mismatch': 1.5,
         }

         url = request.GET.get('url')

         # ── Step 1: Parse & normalize URL ──
         domain = ""
         try:
             parsed_url = urlparse(url)
             domain = parsed_url.netloc.lower()
             if domain.startswith('www.'):
                 domain = domain[4:]
             print(f"Processing domain: {domain}")
         except Exception as e:
             print(f"Error parsing domain: {e}")

         # ── Step 2: Extract features (always run) ──
         try:
             res_temp = np.array(featureExtraction(url))
             res_temp_list = res_temp.tolist()
         except Exception as e:
             print(f"Warning: Could not extract features: {e}")
             res_temp_list = [0] * 29

         # ── Step 3: Reputation check ──
         reputation_result = check_url_reputation(url)
         reputation_verdict = None  # 'phishing', 'legitimate', or None (unknown)
         reputation_source = 'unknown'
         reputation_confidence = 0.5

         if reputation_result:
             reputation_verdict = 'phishing' if reputation_result['is_phishing'] else 'legitimate'
             reputation_source = reputation_result['source']
             reputation_confidence = reputation_result.get('confidence', 0.9)
             print(f"Reputation: {reputation_verdict} from {reputation_source} (conf: {reputation_confidence})")

         # ── Step 4: ML model prediction ──
         ml_verdict = None
         ml_confidence = 0.5
         try:
             model = PhishingurldetectionappConfig.model
             # Handle backwards compatibility: old 15-feature model vs new 25-feature model
             n_model_features = getattr(model, 'n_features_in_', len(feature_names))
             ml_feature_names = feature_names[:n_model_features]
             ml_features = res_temp_list[:n_model_features]
             testdata = pd.DataFrame([ml_features], columns=ml_feature_names)
             ml_prediction = int(model.predict(testdata)[0])
             ml_verdict = 'phishing' if ml_prediction == 1 else 'legitimate'

             if hasattr(model, 'predict_proba'):
                 proba = model.predict_proba(testdata)[0]
                 if len(proba) == 2:
                     ml_confidence = float(proba[1]) if ml_prediction == 1 else float(proba[0])
                 else:
                     ml_confidence = 0.75
             else:
                 ml_confidence = 0.75
             print(f"ML model: {ml_verdict} (conf: {ml_confidence:.2f})")
         except Exception as e:
             print(f"ML model error: {e}")

         # ── Step 5: Weighted feature score (for override decisions) ──
         weighted_feature_score = sum(
             FEATURE_WEIGHTS.get(name, 1.0) * (1 if val >= 1 else 0)
             for name, val in zip(feature_names, res_temp_list)
         )

         # ── Step 6: Ensemble decision ──
         final_verdict = 'legitimate'
         final_confidence = 0.5
         detection_source = 'ensemble'

         if reputation_verdict == 'phishing' and ml_verdict == 'phishing':
             # Both agree: phishing — high confidence
             final_verdict = 'phishing'
             final_confidence = max(reputation_confidence, ml_confidence)
             detection_source = f"{reputation_source}+ml_model"

         elif reputation_verdict == 'phishing' and ml_verdict == 'legitimate':
             # Reputation says phishing, ML disagrees — trust reputation (external has higher precision)
             final_verdict = 'phishing'
             final_confidence = reputation_confidence * 0.85
             detection_source = reputation_source

         elif reputation_verdict == 'legitimate' and ml_verdict == 'phishing':
             # ML says phishing, reputation says clean
             if weighted_feature_score >= 6.0:
                 # Feature evidence supports ML — override reputation
                 # (Safe Browsing "not found" ≠ confirmed safe)
                 final_verdict = 'phishing'
                 final_confidence = ml_confidence * 0.8
                 detection_source = 'ml_model+features'
             else:
                 # Weak feature evidence — trust reputation, flag as suspicious
                 final_verdict = 'suspicious'
                 final_confidence = min(reputation_confidence, 0.7)
                 detection_source = f"{reputation_source}+ml_disagree"

         elif reputation_verdict == 'legitimate' and ml_verdict == 'legitimate':
             # Both agree: legitimate
             final_verdict = 'legitimate'
             final_confidence = max(reputation_confidence, ml_confidence)
             detection_source = f"{reputation_source}+ml_model"

         elif reputation_verdict is None and ml_verdict is not None:
             # No reputation data — use ML result, but override if features
             # show strong phishing signals that the model missed.
             if ml_verdict == 'legitimate' and weighted_feature_score >= 7.0:
                 final_verdict = 'phishing'
                 final_confidence = min(0.85, weighted_feature_score / 15.0)
                 detection_source = 'feature_override'
             else:
                 final_verdict = ml_verdict
                 final_confidence = ml_confidence
                 detection_source = 'ml_model'

         elif reputation_verdict is not None and ml_verdict is None:
             # ML failed — use reputation only
             final_verdict = reputation_verdict
             final_confidence = reputation_confidence
             detection_source = reputation_source

         else:
             # Both failed — inconclusive
             final_verdict = 'inconclusive'
             final_confidence = 0.5
             detection_source = 'error_no_data'

         # ── Build response ──
         if final_verdict == 'phishing':
             PredictionMade = 1
             url_success_rate = round((1 - final_confidence) * 100, 2)
             url_phished_rate = round(final_confidence * 100, 2)
         elif final_verdict == 'inconclusive':
             PredictionMade = -1
             url_success_rate = 50.0
             url_phished_rate = 50.0
         else:
             PredictionMade = 0
             url_success_rate = round(final_confidence * 100, 2)
             url_phished_rate = round((1 - final_confidence) * 100, 2)

         # Save scan result
         db_result = 'phishing' if final_verdict == 'phishing' else ('suspicious' if final_verdict == 'inconclusive' else 'legitimate')
         
         user = request.user if request.user.is_authenticated else None
         scan_result = ScanResult.objects.create(
             user=user,
             scan_type='url', target=url, result=db_result,
             risk_score=url_phished_rate, detection_source=detection_source
         )

         response_dict = {
             "url": url,
             "scanId": scan_result.id,
             "featureExtractionResult": res_temp_list,
             "predictionMade": PredictionMade,
             "successRate": url_success_rate,
             "phishRate": url_phished_rate,
             "detectionSource": detection_source
         }
         print(response_dict)
         return Response(response_dict, status=200)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
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
        
        # Combine results — when raw headers are not provided, use content
        # score only to avoid phantom points from missing auth checks.
        has_raw_headers = header_analysis.get('has_raw_headers', False)

        if has_raw_headers:
            combined_risk_score = (header_analysis['risk_score'] * 0.4
                                   + content_analysis['risk_score'] * 0.6)
        else:
            combined_risk_score = content_analysis['risk_score']

        combined_risk_score = min(combined_risk_score, 100)

        if combined_risk_score >= 70:
            risk_level = 'High Risk'
        elif combined_risk_score >= 45:
            risk_level = 'Medium Risk'
        elif combined_risk_score >= 20:
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
        
        user = request.user if request.user.is_authenticated else None
        ScanResult.objects.create(user=user, scan_type='email', target=sender, result=email_result, risk_score=combined_risk_score, detection_source='email_analysis')

        return Response(result)
        
    except Exception as e:
        return Response({'error': str(e)}, status=400)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def submit_feedback(request):
    """Accept user feedback on a scan prediction."""
    scan_id = request.data.get('scan_id')
    feedback = request.data.get('feedback')       # 'correct' or 'incorrect'
    label = request.data.get('label')             # 'phishing' or 'legitimate'

    if not scan_id or feedback not in ('correct', 'incorrect'):
        return Response({'error': 'scan_id and feedback (correct/incorrect) are required'},
                        status=status.HTTP_400_BAD_REQUEST)
    if label and label not in ('phishing', 'legitimate'):
        return Response({'error': 'label must be phishing or legitimate'},
                        status=status.HTTP_400_BAD_REQUEST)

    try:
        scan = ScanResult.objects.get(id=scan_id)
    except ScanResult.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)

    scan.user_feedback = feedback
    if label:
        scan.feedback_label = label
    elif feedback == 'correct':
        scan.feedback_label = scan.result if scan.result in ('phishing', 'legitimate') else None
    else:
        # Incorrect — flip the label
        scan.feedback_label = 'legitimate' if scan.result == 'phishing' else 'phishing'
    scan.save()

    return Response({'status': 'ok', 'feedback_label': scan.feedback_label})


@api_view(['GET'])
def health_check(request):
    """Health check endpoint for Azure App Service monitoring and uptime probes."""
    import time
    from django.db import connection

    health = {
        'status': 'healthy',
        'timestamp': time.time(),
        'services': {},
    }

    # Database
    try:
        connection.ensure_connection()
        health['services']['database'] = 'ok'
    except Exception as e:
        health['services']['database'] = f'error: {e}'
        health['status'] = 'degraded'

    # ML model
    try:
        model = PhishingurldetectionappConfig.model
        if model is not None:
            health['services']['ml_model'] = 'ok'
        else:
            health['services']['ml_model'] = 'not loaded'
            health['status'] = 'degraded'
    except Exception as e:
        health['services']['ml_model'] = f'error: {e}'
        health['status'] = 'degraded'

    http_status = 200 if health['status'] == 'healthy' else 503
    return Response(health, status=http_status)


@api_view(['GET'])
def model_status(request):
    """Return current model metadata and feedback stats."""
    import json as _json
    metadata_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'phishingUrlDetectionBackend', 'model', 'model_metadata.json'
    )
    metadata = {}
    if os.path.exists(metadata_path):
        with open(metadata_path, 'r') as f:
            metadata = _json.load(f)

    model = PhishingurldetectionappConfig.model
    n_features = getattr(model, 'n_features_in_', 'unknown')

    total_feedback = ScanResult.objects.filter(user_feedback__isnull=False).count()
    incorrect_feedback = ScanResult.objects.filter(user_feedback='incorrect').count()

    return Response({
        'model_features': n_features,
        'metadata': metadata,
        'feedback_stats': {
            'total_feedback': total_feedback,
            'incorrect_reports': incorrect_feedback,
        }
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def dashboard_stats(request):
    """Return live dashboard statistics from actual scan history."""
    from django.db.models import Count, Avg
    from django.db.models.functions import TruncDate
    import json

    qs = ScanResult.objects.filter(user=request.user)
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