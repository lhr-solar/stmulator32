#!/bin/bash

# Check and install requirements needed for this repository
# Mostly CMake / Make / possibly gcc things as needed.

# Function to check if a package is installed
check_installed() {
    dpkg -l | grep -q "^ii  $1" && echo "$1 is installed." || echo "$1 is NOT installed."
}

# Check deps
echo "Checking dependencies..."
check_installed g++
check_installed cmake
check_installed make
check_installed libcapstone4 # at least on my machine...
check_installed libcapstone-dev

# Install missing packages
missing_packages=()

if ! dpkg -l | grep -q "^ii  g++"; then
    missing_packages+=("g++")
fi

if ! dpkg -l | grep -q "^ii  cmake"; then
    missing_packages+=("cmake")
fi

if ! dpkg -l | grep -q "^ii  make"; then
    missing_packages+=("make")
fi

if ! dpkg -l | grep -q "^ii  libcapstone"; then
    missing_packages+=("libcapstone4")
fi

if ! dpkg -l | grep -q "^ii  libcapstone-dev"; then
    missing_packages+=("libcapstone-dev")
fi

if [ ${#missing_packages[@]} -eq 0 ]; then
    echo "All required packages are installed."
else
    echo "The following packages are missing: ${missing_packages[*]}"
    read -p "Do you want to install them? (y/n): " choice
    if [ "$choice" == "y" ]; then
        sudo apt update
        sudo apt install -y "${missing_packages[@]}"
    else
        echo "Exiting without installing missing packages."
    fi
fi
