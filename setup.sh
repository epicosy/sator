#!/bin/bash
# this script sets the tenet application for it to work properly

ROOT_DIR=~/.sator/

# the two main directories are: config
mkdir -p "${ROOT_DIR}/config"

# the configuration file and tables must be correctly placed in the respective location
cp -a sator/config/. "${ROOT_DIR}/config"
