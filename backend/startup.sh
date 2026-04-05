#!/bin/bash
set -e

# Activate the virtualenv created by Azure's Oryx build
if [ -f /home/site/wwwroot/antenv/bin/activate ]; then
    echo "Activating virtual environment..."
    source /home/site/wwwroot/antenv/bin/activate
fi

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput

# Create superuser if env vars are set
if [ "$CREATE_SUPERUSER" = "true" ]; then
    echo "Creating superuser..."
    python -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishingUrlDetectionBackend.settings')
django.setup()
from django.contrib.auth.models import User
username = os.environ.get('SUPERUSER_USERNAME')
email = os.environ.get('SUPERUSER_EMAIL')
password = os.environ.get('SUPERUSER_PASSWORD')
if username and not User.objects.filter(username=username).exists():
    User.objects.create_superuser(username=username, email=email, password=password)
    print(f'Superuser {username} created successfully')
else:
    print(f'Superuser {username} already exists or not configured')
"
fi

echo "Starting Gunicorn on port 8000..."
gunicorn phishingUrlDetectionBackend.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 2 \
    --timeout 120 \
    --access-logfile '-' \
    --error-logfile '-'
