#!/bin/bash
cd /var/www/Lead-Your-Way
git pull
uv sync
uv run python manage.py migrate
uv run python manage.py collectstatic --noinput
sudo systemctl restart leadyourway.service leadyourway-worker.service
echo "Deployment of Lead-Your-Way complete!"
