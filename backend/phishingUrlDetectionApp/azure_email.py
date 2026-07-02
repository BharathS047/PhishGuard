"""
Utility for sending transactional email (OTP verification codes, password
reset codes, etc.).

Provider priority:
  1. Resend (https://resend.com) via its HTTP API  -- preferred
  2. Azure Communication Services                  -- legacy fallback
  3. Console output                                -- local development

(The module keeps its historical name for import stability; it is no longer
Azure-specific.)
"""

import logging
import requests
from django.conf import settings as django_settings

logger = logging.getLogger(__name__)

RESEND_ENDPOINT = 'https://api.resend.com/emails'


def send_email(subject, plain_text, recipient_email):
    """
    Send a plain-text email through the first configured provider.

    Raises the underlying provider error if sending fails (callers are expected
    to handle failures — e.g. registration rolls back and returns a 503).
    """
    resend_api_key = getattr(django_settings, 'RESEND_API_KEY', '')
    resend_from = getattr(django_settings, 'RESEND_FROM_ADDRESS', '')
    connection_string = getattr(django_settings, 'AZURE_COMMUNICATION_CONNECTION_STRING', '')
    sender_address = getattr(django_settings, 'AZURE_EMAIL_SENDER_ADDRESS', '')

    # 1) Resend (preferred)
    if resend_api_key:
        resp = requests.post(
            RESEND_ENDPOINT,
            headers={
                'Authorization': f'Bearer {resend_api_key}',
                'Content-Type': 'application/json',
            },
            json={
                'from': resend_from,
                'to': [recipient_email],
                'subject': subject,
                'text': plain_text,
            },
            timeout=15,
        )
        if resp.status_code >= 400:
            logger.error('Resend send failed (%s): %s', resp.status_code, resp.text[:500])
            resp.raise_for_status()
        logger.info('Resend email sent to %s — id: %s', recipient_email, resp.json().get('id', 'N/A'))
        return

    # 2) Azure Communication Services (legacy fallback)
    if connection_string:
        from azure.communication.email import EmailClient

        client = EmailClient.from_connection_string(connection_string)
        message = {
            "senderAddress": sender_address,
            "recipients": {"to": [{"address": recipient_email}]},
            "content": {"subject": subject, "plainText": plain_text},
        }
        poller = client.begin_send(message)
        result = poller.result()
        logger.info('Azure email sent to %s — message ID: %s', recipient_email, result.get('id', 'N/A'))
        return

    # 3) Local development — print to console
    logger.warning('No email provider configured (RESEND_API_KEY / ACS) — printing email to console.')
    print(f'\n{"="*60}')
    print(f'To:      {recipient_email}')
    print(f'Subject: {subject}')
    print(f'{"-"*60}')
    print(plain_text)
    print(f'{"="*60}\n')
