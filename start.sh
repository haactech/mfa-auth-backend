#!/bin/sh

# Esperar unos segundos para asegurarnos de que todo está listo
sleep 2

# Aplicar migraciones
echo "Applying database migrations..."
python manage.py migrate

# Recolectar archivos estáticos
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Iniciar Gunicorn
echo "Starting Gunicorn..."
gunicorn --bind 0.0.0.0:8000 core.wsgi:application