# 🕵️‍♂️ Impawnd-OSINT-beta  
Herramienta OSINT con interfaz gráfica (tkinter) para Ubuntu.  
Geolocaliza IPs y teléfonos, reconstruye usuarios, lanza nmap, whois, traceroute, DNS-lookup… todo desde un clic.

&gt; 🚧 Versión IOS y version de termux en desarrollo.

![Licencia](https://img.shields.io/badge/licencia-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![Plataforma](https://img.shields.io/badge/plataforma-Ubuntu%20%7C%20-lightgrey.svg)

---

## ✅ Funciones rápidas
- **Geolocalizar IP** → país, ciudad, ISP, coordenadas + Google-Earth  
- **Geolocalizar teléfono** → país, operador, línea (vía Numverify)  
- **Whois, Ping, Traceroute, DNS Lookup**  
- **Nmap** con perfiles: `-F`, `-A`, `-sV`, `-O`, etc.  
- **OSINT usuario** → GitHub, Twitter, Instagram, Facebook, Roblox  
- **Accesos rápidos** a Shodan, HaveIBeenPwned, VirusTotal, crt.sh…

---

## 📦 Instalación en Ubuntu (20.04 / 22.04 / 24.04)
```bash
# 1. Actualiza e instala dependencias
sudo apt update && sudo apt install -y python3 python3-tk python3-pip git

# 2. Clona el repositorio
git clone https://github.com/664mani/impawnd-osint-beta.git
cd impawnd-osint-beta

# 3. Instala la librería externa
pip3 install -r requirements.txt

# 4. ¡Ejecuta!
python3 osint_toolkit.py
