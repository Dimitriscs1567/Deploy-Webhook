#!/bin/bash
cd /home/deploy/Lead-Your-Way-Frontend
git pull
cp -R build/web/* /var/www/Lead-Your-Way-Frontend/
sudo /bin/systemctl reload nginx.service
echo "Deployment of Lead-Your-Way-Frontend complete!"
