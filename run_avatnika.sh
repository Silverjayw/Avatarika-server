#!/bin/bash

GAME_DIR="/home/sanitar/.local/share/Steam/steamapps/common/AVATARIKA"
CLIENT="$GAME_DIR/client.exe"

echo "Starting AVATARIKA client..."

wine "$CLIENT" \
  "/24B3D4DC-BA6D-4ECD-94D5-F7C2F9EDDE7B" \
  "/gamexp_sid 00000000-0000-0000-0000-000000000000" \
  "/pid $$" \
  "/locale en_US" \
  "/distributor GameXP"
