#!/bin/bash

if [ -z "$1" ]; then
  echo "No latest_tag in arguments."
  echo "Example: ./add_theme_to_keycloak.sh 20.0.1"
  exit 1
fi

latest_tag=$1

keycloak_dir="./keycloak-${latest_tag}/themes"
source_email="/home/user/app/ozgsec-keycloak-main/build_keycloak/src/main/resources/theme/ozgsec-keycloak-theme/email"
source_login="/home/user/app/ozgsec-keycloak-main/build_keycloak/src/main/resources/theme/ozgsec-keycloak-theme/login"

mkdir -p "$keycloak_dir"
cp -r "$source_email" "$keycloak_dir"
cp -r "$source_login" "$keycloak_dir"

echo "Themes were added successfully to your Keycloak installation."
