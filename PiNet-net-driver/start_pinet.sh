#!/bin/bash

echo "Restarting PiNet driver..."

# Step 1: Unload previous module (if any)
if [ -f ./unload_pinet.sh ]; then
    ./unload_pinet.sh
else
    echo "Warning: unload_pinet.sh not found!"
fi

# Step 2: Clean previous builds
echo "Running make clean..."
make clean

# Step 3: Compile the kernel module
echo "Building PiNet kernel module..."
if make; then
    echo "Build successful."
else
    echo "Build failed. Exiting."
    exit 1
fi

# Step 4: Load the module
if [ -f ./load_pinet.sh ]; then
    ./load_pinet.sh
else
    echo "Warning: load_pinet.sh not found!"
fi

echo "PiNet driver restarted successfully."
