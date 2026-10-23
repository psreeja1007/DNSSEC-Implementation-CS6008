#!/bin/bash
set -e
echo "[webserver] serving /var/www/html on :80"
exec python3 -m http.server 80 --directory /var/www/html
