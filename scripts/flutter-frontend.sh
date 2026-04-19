#!/bin/bash
set -euo pipefail
cd /home/deploy/frontend
git fetch origin deploy
git reset --hard origin/deploy
rsync -a --delete build/web/ /var/www/frontend/
echo "Frontend deploy complete."