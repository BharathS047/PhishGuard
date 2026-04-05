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

echo "Starting Gunicorn on port 8000..."
gunicorn phishingUrlDetectionBackend.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 2 \
    --timeout 120 \
    --access-logfile '-' \
    --error-logfile '-'
