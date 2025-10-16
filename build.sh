#!/bin/bash

# Script para empaquetar la aplicación OSINT en un solo ejecutable usando PyInstaller

# 1. Instalar dependencias
echo "--- Instalando dependencias desde requirements.txt ---"
pip install --upgrade pip
pip install -r requirements.txt

# 2. Ejecutar PyInstaller
echo "--- Empaquetando la aplicación con PyInstaller ---"
pyinstaller --name ImpawndOSINT \
            --onefile \
            --windowed \
            osint_toolkit.py

# 3. Limpiar
echo "--- Limpiando archivos de compilación ---"
rm -rf build/
rm -f ImpawndOSINT.spec

echo "--- ¡Compilación completada! El ejecutable está en la carpeta 'dist/' ---"