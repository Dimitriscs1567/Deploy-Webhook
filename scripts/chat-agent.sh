#!/bin/bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
cd /var/www/chat-agent
git fetch origin prod
git merge --ff-only origin/prod
uv sync --frozen
uv run python manage.py migrate --noinput
uv run python manage.py collectstatic --noinput
sudo /bin/systemctl restart chat-agent.service
sudo /bin/systemctl restart chat-agent-worker.service
echo "Backend deploy complete."