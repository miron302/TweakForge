#!/usr/bin/env bash
# TweakForge launcher: first run installs everything, then opens the menu.
cd "$(dirname "$0")"
command -v python3 >/dev/null || sudo pacman -S --needed --noconfirm python
exec python3 tweakforge.py "$@"
