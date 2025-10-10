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
---

## 🔧 Solución de problemas

| Problema | Solución rápida |
|---|---|
| `error: externally-managed-environment` | Usa un entorno virtual:<br>`python3 -m venv venv && source venv/bin/activate && pip install requests` |
| `No module named 'tkinter'` | Instala el paquete gráfico:<br>`sudo apt install python3-tk` |
| `python3: can't open file 'osint_toolkit.py'` | Asegúrate de estar dentro de la carpeta del repo:<br>`cd impawnd-osint-beta` |
| `Permission denied` | Da permisos de ejecución:<br>`chmod +x osint_toolkit.py` |
| Google Earth no se abre | Instala el paquete `xdg-utils`:<br>`sudo apt install xdg-utils` o abre el enlace manual que aparece en consola |
| Numverify devuelve “Error” | La demo-key tiene límite; consigue tu clave gratis en [numverify.com](https://numverify.com) y cámbiala en el script |

¿Sigues atascado?  
Abre un issue con el **mensaje completo** de error y tu sistema operativo.
