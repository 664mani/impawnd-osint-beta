# 🕵️‍♂️ Impawnd-OSINT-beta  

V3.0 BETA YA DISPONIBLE

Herramienta OSINT con interfaz gráfica (tkinter) para Ubuntu.  
Geolocaliza IPs y teléfonos, reconstruye usuarios, lanza nmap, whois, traceroute, DNS-lookup… todo desde un clic.

&gt; 🚧 Versión IOS y version de termux en desarrollo. ESTA ES LA VERSIÓN BETA .

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
- ## 🔧 Solución de problemas

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

---
---

## 🔑 API Key – geolocalización de teléfonos
El script utiliza **Numverify** (100 consultas/mes gratis).  
Demo-key incluida → puede agotarse.

| Paso | Acción |
|---|---|
| 1 | Regístrate gratis en [https://numverify.com](https://numverify.com) |
| 2 | Copia tu **Access Key** del dashboard |
| 3 | Abre `osint_toolkit.py` y cambia la línea:  
  `API_KEY_NUMVERIFY = "tu_clave_aquí"` |
  ---
## 📝 Paso a paso: cambiar tu token de Numverify

1. **Abre el archivo**  
   ```bash
   nano osint_toolkit.py
2. Busca la línea
  Presiona Ctrl + W, escribe
  API_KEY_NUMVERIFY
  y pulsa Enter.
3.Reemplaza solo el contenido entre comillas

  Antes

  API_KEY_NUMVERIFY = "ef9d9159f8b256ad18d6752773d4e6a3"

  Después

  API_KEY_NUMVERIFY = "TU_CLAVE_AQUÍ"

4. Guarda y cierra

    Ctrl + O → Enter → Ctrl + X
   
5. Comprueba:

   python3 osint_toolkit.py

---
[![Instagram](https://img.shields.io/badge/Instagram-%23E4405F.svg?logo=Instagram&logoColor=white)](https://instagram.com/maxht_123)
## 📲 Redes del autor
- **Instagram**: [@maxht_123](https://instagram.com/maxht_123)  
  ** Si quieres reportar algo aqui me puedes encontrar **

> Numverify solo devuelve **país, operador y línea**; **NUNCA** la ubicación exacta del usuario.
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

---

