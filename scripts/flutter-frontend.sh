#!/bin/bash
set -euo pipefail
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <folder>" >&2
  exit 1
fi
FOLDER="$1"
cd "/home/deploy/$FOLDER"
git fetch origin deploy
git reset --hard origin/deploy
rsync -a --delete build/web/ "/var/www/$FOLDER/"
echo "Frontend deploy complete."
