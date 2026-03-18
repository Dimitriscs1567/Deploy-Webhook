#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
cd /var/www/Lead-Your-Way
git pull
uv sync
uv run python manage.py migrate
uv run python manage.py collectstatic --noinput
sudo /bin/systemctl restart leadyourway.service
sudo /bin/systemctl restart leadyourway-worker.service
echo "Deployment of Lead-Your-Way complete!"
