#!/bin/bash
cd Lead-Your-Way-Frontend
git pull
cp -R build/web/* /var/www/Lead-Your-Way-Frontend/
systemctl restart nginx.service
echo "Deployment of Lead-Your-Way-Frontend complete!"
