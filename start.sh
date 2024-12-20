#!/bin/sh

# Esperar unos segundos para asegurarnos de que todo está listo
sleep 2

#!/bin/bash

echo "Applying database migrations..."
python manage.py makemigrations authentication
python manage.py migrate

echo "Collecting static files..."
mkdir -p staticfiles
python manage.py collectstatic --noinput

echo "Starting Gunicorn server..."
gunicorn core.wsgi:application --bind 0.0.0.0:8000