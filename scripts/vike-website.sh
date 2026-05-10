#!/bin/bash
set -euo pipefail
cd /var/www/commercial-website
git fetch origin prod
git merge --ff-only origin/prod
npm ci
sudo systemctl restart commercial-website
echo "Deployment of Lead-Your-Way-Website complete!"