"""
Utility for sending emails via Azure Communication Services.

Falls back to console output when AZURE_COMMUNICATION_CONNECTION_STRING
is not configured (local development).
"""

import logging
from django.conf import settings as django_settings

logger = logging.getLogger(__name__)


def send_email(subject, plain_text, recipient_email):
    """
    Send an email using Azure Communication Services.

    Parameters
    ----------
    subject : str
        Email subject line.
    plain_text : str
        Plain-text body of the email.
    recipient_email : str
        Recipient email address.

    Raises
    ------
    Exception
        If Azure Email sending fails and fail_silently is not desired.
    """
    connection_string = getattr(django_settings, 'AZURE_COMMUNICATION_CONNECTION_STRING', '')
    sender_address = getattr(django_settings, 'AZURE_EMAIL_SENDER_ADDRESS', '')

    # Fallback for local development — print to console
    if not connection_string:
        logger.warning('AZURE_COMMUNICATION_CONNECTION_STRING not set — printing email to console.')
        print(f'\n{"="*60}')
        print(f'To:      {recipient_email}')
        print(f'From:    {sender_address or "not configured"}')
        print(f'Subject: {subject}')
        print(f'{"-"*60}')
        print(plain_text)
        print(f'{"="*60}\n')
        return

    from azure.communication.email import EmailClient

    client = EmailClient.from_connection_string(connection_string)

    message = {
        "senderAddress": sender_address,
        "recipients": {
            "to": [{"address": recipient_email}],
        },
        "content": {
            "subject": subject,
            "plainText": plain_text,
        },
    }

    poller = client.begin_send(message)
    result = poller.result()
    logger.info('Azure email sent to %s — message ID: %s', recipient_email, result.get('id', 'N/A'))
