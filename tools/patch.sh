#!/bin/bash

# --- CONFIGURATION ---
# Name of the challenge binary
BIN_FILE="vuln"
# Name of the loader/linker (usually ld-linux-x86-64.so.2)
LOADER="./ld-linux-x86-64.so.2"

# --- CHECK DEPENDENCIES ---
if ! command -v patchelf &> /dev/null; then
    echo "❌ Error: 'patchelf' is not installed."
    echo "👉 Please run: sudo apt install patchelf"
    exit 1
fi

if [ ! -f "$BIN_FILE" ]; then
    echo "❌ Error: File '$BIN_FILE' not found in the current directory."
    exit 1
fi

echo "🔄 Starting patch process..."

# 1. Grant execution permissions to everything
echo "Step 1: Setting executable permissions (chmod +x)..."
chmod +x ./*.so* "$BIN_FILE"

# 2. Patch the Main Binary (Interpreter + Rpath)
echo "Step 2: Patching binary '$BIN_FILE'..."
patchelf --set-interpreter "$LOADER" --set-rpath . "$BIN_FILE"

# 3. Patch the C++ Library (Fixes dependency chain for libm)
if [ -f "./libstdc++.so.6" ]; then
    echo "Step 3: Patching libstdc++.so.6 (setting RPATH)..."
    patchelf --set-rpath . ./libstdc++.so.6
fi

# 4. Patch the Math Library (Optional safety measure)
if [ -f "./libm.so.6" ]; then
    echo "Step 4: Patching libm.so.6 (setting RPATH)..."
    patchelf --set-rpath . ./libm.so.6
fi

echo "✅ Patching complete!"
echo "---------------------------------------------------"
echo "🔍 Verifying with ldd:"
ldd "$BIN_FILE"
echo "---------------------------------------------------"
echo "🚀 You can now run: ./$BIN_FILE"
