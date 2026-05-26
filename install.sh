#!/bin/bash
set -e

APP_DIR=/home/ubuntu/midterm
SERVICE_FILE=notes-app.service

sudo mkdir -p "$APP_DIR"
sudo cp -r . "$APP_DIR"
sudo chown -R root:root "$APP_DIR"
sudo cp "$APP_DIR/$SERVICE_FILE" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_FILE"
sudo systemctl start "$SERVICE_FILE"