# 🕵️‍♂️ Impawnd-OSINT v4.0 – Rediseño

Herramienta OSINT de escritorio con una interfaz gráfica moderna y modular.

![Licencia](https://img.shields.io/badge/licencia-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![Plataforma](https://img.shields.io/badge/plataforma-Cross--Platform-lightgrey.svg)

---

## ✨ Características

- **Interfaz Gráfica Moderna**: Diseño "Cyber-Neón" con pestañas para una fácil navegación.
- **Modular y Extensible**: Organizado en pestañas (Red, OSINT, Web) para añadir nuevas herramientas fácilmente.
- **Multi-hilo**: Ejecuta múltiples herramientas simultáneamente sin congelar la interfaz.
- **Empaquetado**: Incluye un script para crear un ejecutable de un solo archivo.

## 🛠️ Herramientas Incluidas

- **Red**: Ping, Whois, Nmap (rápido e intenso), Traceroute.
- **OSINT**: Geolocalización de IP, búsqueda en Shodan.
- **Web**: WhatWeb, escáner de SSL Labs.

---

## 📦 Instalación y Uso

### Opción 1: Ejecutar desde el código fuente

1.  **Clona el repositorio:**
    ```bash
    git clone https://github.com/664mani/impawnd-osint-beta.git
    cd impawnd-osint-beta
    ```

2.  **Instala las dependencias:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Ejecuta la aplicación:**
    ```bash
    python osint_toolkit.py
    ```

### Opción 2: Compilar el ejecutable

1.  **Clona el repositorio y entra en el directorio.**

2.  **Ejecuta el script de compilación:**
    ```bash
    chmod +x build.sh
    ./build.sh
    ```

3.  **Encuentra el ejecutable en la carpeta `dist/`.**

---

## 🔧 Dependencias del Sistema

Asegúrate de tener las siguientes herramientas de línea de comandos instaladas y en tu PATH para que la aplicación funcione correctamente:

- `ping`
- `whois`
- `nmap`
- `traceroute`
- `whatweb`

Puedes instalarlas en sistemas basados en Debian/Ubuntu con:
```bash
sudo apt update && sudo apt install -y inetutils-ping whois nmap traceroute whatweb
```

---

## 🖼️ Capturas de Pantalla (Próximamente)

*(Se añadirán capturas de la nueva interfaz)*