#!/bin/bash
cd /var/www/Lead-Your-Way-Website
git pull
npm install
pm2 reload lead-your-way-website
echo "Deployment complete!"
