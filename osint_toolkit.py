import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import webbrowser
import time
import threading

# Lista de herramientas OSINT externas (se abren en navegador)
OSINT_TOOLS = [
    ("Shodan", "https://www.shodan.io/"),
    ("Have I Been Pwned", "https://haveibeenpwned.com/"),
    ("Hunter.io", "https://hunter.io/"),
    ("theHarvester", "https://github.com/laramies/theHarvester"),
    ("Maltego", "https://www.maltego.com/"),
    ("SpiderFoot", "https://www.spiderfoot.net/"),
    ("Censys", "https://censys.io/"),
    ("Google Dorks", "https://www.exploit-db.com/google-hacking-database"),
    ("Social Searcher", "https://www.social-searcher.com/"),
    ("Recon-ng", "https://github.com/lanmaster53/recon-ng"),
    ("OSINT Framework", "https://osintframework.com/"),
    ("IntelX", "https://intelx.io/"),
    ("URLScan", "https://urlscan.io/"),
    ("Pipl", "https://pipl.com/"),
    ("Creepy", "https://github.com/ilektrojohn/creepy"),
    ("Sherlock", "https://github.com/sherlock-project/sherlock"),
]

# Herramientas funcionales internas
FUNC_TOOLS = [
    "Nmap (escaneo rápido)",
    "Geolocalizar IP",
    "Geolocalizar teléfono",
    "Hydra",
    "SQLMap",
    "Whois",
    "Ping",
    "Traceroute",
    "DNS Lookup",
    "Buscar usuario en GitHub",
    "Buscar usuario en Twitter",
    "Buscar usuario en Instagram",
    "Buscar usuario en Facebook",
    "Buscar email en HaveIBeenPwned",
    "Buscar dominio en VirusTotal",
    "Buscar IP en AbuseIPDB",
    "Buscar dominio en SSL Labs",
    "Buscar dominio en ThreatCrowd",
    "Buscar dominio en crt.sh",
    "Buscar dominio en SecurityTrails",
    "Buscar dominio en Robtex",
]

def open_tool(url):
    webbrowser.open(url)

def run_nmap_scan(target, params):
    try:
        cmd = ['nmap'] + params.split() + [target]
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return result
    except Exception as e:
        return f"Error ejecutando Nmap: {str(e)}"

def run_whois_lookup(target):
    try:
        result = subprocess.check_output(['whois', target], stderr=subprocess.STDOUT, text=True)
        return result
    except Exception as e:
        return f"Error ejecutando Whois: {str(e)}"

def run_ping(target):
    try:
        result = subprocess.check_output(['ping', '-c', '4', target], stderr=subprocess.STDOUT, text=True)
        return result
    except Exception as e:
        return f"Error ejecutando Ping: {str(e)}"

def run_traceroute(target):
    try:
        result = subprocess.check_output(['traceroute', target], stderr=subprocess.STDOUT, text=True)
        return result
    except Exception as e:
        return f"Error ejecutando Traceroute: {str(e)}"

def run_dns_lookup(target):
    try:
        result = subprocess.check_output(['nslookup', target], stderr=subprocess.STDOUT, text=True)
        return result
    except Exception as e:
        return f"Error ejecutando DNS Lookup: {str(e)}"

def search_github_user(username):
    webbrowser.open(f"https://github.com/{username}")
    return f"Abriendo perfil de GitHub: https://github.com/{username}"

def search_twitter_user(username):
    webbrowser.open(f"https://twitter.com/{username}")
    return f"Abriendo perfil de Twitter: https://twitter.com/{username}"

def search_instagram_user(username):
    webbrowser.open(f"https://instagram.com/{username}")
    return f"Abriendo perfil de Instagram: https://instagram.com/{username}"

def search_facebook_user(username):
    webbrowser.open(f"https://facebook.com/{username}")
    return f"Abriendo perfil de Facebook: https://facebook.com/{username}"

def search_roblox_user(username):
    webbrowser.open(f"https://www.roblox.com/users/{username}/profile")
    return f"abriendo perfil de Roblox: https:www.roblox.com/users/{username}/profile"

def search_hibp_email(email):
    return "Funcionalidad requiere API Key de HaveIBeenPwned. No implementada por seguridad."

def search_virustotal_domain(domain):
    return "Funcionalidad requiere API Key de VirusTotal. No implementada por seguridad."

def search_abuseipdb_ip(ip):
    return "Funcionalidad requiere API Key de AbuseIPDB. No implementada por seguridad."

def search_ssllabs_domain(domain):
    return "Consulta en navegador."
    
def search_threatcrowd_domain(domain):
    return "Consulta en navegador."

def search_crtsh_domain(domain):
    return "Consulta en navegador."

def search_securitytrails_domain(domain):
    return "Consulta en navegador."

def search_robtex_domain(domain):
    return "Consulta en navegador."

default_nmap_params = "-F"

def run_hydra(target, params):
    try:
        cmd = ['hydra'] + params.split() + [target]
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return result
    except Exception as e:
        return f"Error ejecutando Hydra: {str(e)}"

def run_sqlmap(target, params):
    try:
        cmd = ['sqlmap', '-u', target] + params.split()
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return result
    except Exception as e:
        return f"Error ejecutando sqlmap: {str(e)}"

def geolocate_ip(ip):
    try:
        import requests
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(f"https://ipapi.co/{ip}/json/", headers=headers)
        if response.status_code == 200:
            data = response.json()
            lat = data.get('latitude')
            lon = data.get('longitude')
            info = (
                f"IP: {data.get('ip')}\n"
                f"Ciudad: {data.get('city')}\n"
                f"Región: {data.get('region')}\n"
                f"País: {data.get('country_name')}\n"
                f"Latitud: {lat}\n"
                f"Longitud: {lon}\n"
                f"ISP: {data.get('org')}\n"
                f"Postal: {data.get('postal')}\n"
            )
            # Abrir Google Earth web con la ubicación después de 5 segundos
            if lat and lon:
                def open_earth():
                    time.sleep(5)
                    url = f"https://earth.google.com/web/search/{lat},{lon}"
                    webbrowser.open(url)
                threading.Thread(target=open_earth).start()
                info += f"\nGoogle Earth se abrirá en 5 segundos: https://earth.google.com/web/search/{lat},{lon}\n"
            return info
        else:
            return f"Error en la consulta: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error geolocalizando IP: {str(e)}"
    
def geolocate_phone(phone):
    import requests
    API_KEY = "ef9d9159f8b256ad18d6752773d4e6a3"  # <-- Regístrate en https://numverify.com/
    url = f"http://apilayer.net/api/validate?access_key={API_KEY}&number={phone}&format=1"
    try:
        response = requests.get(url)
        data = response.json()
        if data.get("valid"):
            info = (
                f"Número: {data.get('local_format')}\n"
                f"País: {data.get('country_name')} ({data.get('country_code')})\n"
                f"Ubicación: {data.get('location')}\n"
                f"Operador: {data.get('carrier')}\n"
                f"Línea: {data.get('line_type')}\n"
            )
            return info
        else:
            return "Número no válido o no encontrado."
    except Exception as e:
        return f"Error geolocalizando teléfono: {str(e)}"

def osint_user_info(query):
    import requests
    info = f"Resultados OSINT para: {query}\n\n"

    # GitHub
    info += "\n[GitHub]\n"
    github_url = f"https://api.github.com/users/{query}"
    try:
        r = requests.get(github_url)
        if r.status_code == 200:
            data = r.json()
            info += f"Nombre: {data.get('name')}\nBio: {data.get('bio')}\nRepositorios: {data.get('public_repos')}\nSeguidores: {data.get('followers')}\nURL: {data.get('html_url')}\n"
        else:
            info += "No encontrado.\n"
    except Exception as e:
        info += f"Error: {str(e)}\n"

    # Twitter (solo URL)
    info += "\n[Twitter]\n"
    info += f"Perfil: https://twitter.com/{query}\n"

    # Instagram (solo URL)
    info += "\n[Instagram]\n"
    info += f"Perfil: https://instagram.com/{query}\n"

    # Facebook (solo URL)
    info += "\n[Facebook]\n"
    info += f"Perfil: https://facebook.com/{query}\n"

    # HaveIBeenPwned (solo URL)
    info += "\n[HaveIBeenPwned]\n"
    info += f"Consulta: https://haveibeenpwned.com/account/{query}\n"

    # Hunter.io (solo URL)
    info += "\n[Hunter.io]\n"
    info += f"Consulta: https://hunter.io/search/{query}\n"

    # Pipl (solo URL)
    info += "\n[Pipl]\n"
    info += f"Consulta: https://pipl.com/search/?q={query}\n"

    # Roblox (solo URL)
    info += "\n[Roblox]\n"
    info += f"Perfil: https://www.roblox.com/users/{query}/profile\n"

    # Localidad por IP (si es IP)
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
        info += "\n[Geolocalización IP]\n"
        info += geolocate_ip(query)

    return info

# Añade la herramienta al listado si no está
if "OSINT usuario/correo/localidad" not in FUNC_TOOLS:
    FUNC_TOOLS.insert(2, "OSINT usuario/correo/localidad")
if "Geolocalizar IP" not in FUNC_TOOLS:
    FUNC_TOOLS.insert(1, "Geolocalizar IP")

root = tk.Tk()
root.title("impawnd security -BETA")
root.geometry("700x700")

frame_top = tk.Frame(root)
frame_top.pack(pady=10)

tk.Label(frame_top, text="Herramienta:", font=("Arial", 12)).pack(side=tk.LEFT, padx=5)
combo_tools = ttk.Combobox(frame_top, values=FUNC_TOOLS, state="readonly", width=35)
combo_tools.current(0)
combo_tools.pack(side=tk.LEFT, padx=5)

tk.Label(frame_top, text="Objetivo:", font=("Arial", 12)).pack(side=tk.LEFT, padx=5)
entry_target = tk.Entry(frame_top, width=30)
entry_target.pack(side=tk.LEFT, padx=5)

tk.Label(frame_top, text="Parámetros Nmap:", font=("Arial", 12)).pack(side=tk.LEFT, padx=5)
entry_params = tk.Entry(frame_top, width=20)
entry_params.pack(side=tk.LEFT, padx=5)
entry_params.insert(0, "-F")  # Valor por defecto

btn_run = tk.Button(frame_top, text="Ejecutar")
btn_run.pack(side=tk.LEFT, padx=5)

# Selector de tema
theme_frame = tk.Frame(root)
theme_frame.pack(pady=5)
tk.Label(theme_frame, text="Tema:").pack(side=tk.LEFT, padx=5)
theme_var = tk.StringVar(value="Oscuro")
theme_selector = ttk.Combobox(theme_frame, textvariable=theme_var, values=["Oscuro", "Claro", "Light"], state="readonly", width=10)
theme_selector.pack(side=tk.LEFT, padx=5)
theme_selector.bind("<<ComboboxSelected>>", lambda e: set_theme(theme_var.get()))

text_output = scrolledtext.ScrolledText(root, width=90, height=20)
text_output.pack(pady=10)

label_tools = tk.Label(root, text="Herramientas OSINT externas", font=("Arial", 16, "bold"))
label_tools.pack(pady=10)

osint_buttons = []
for name, url in OSINT_TOOLS:
    btn = tk.Button(root, text=name, width=40, command=lambda u=url: open_tool(u))
    btn.pack(pady=2)
    osint_buttons.append(btn)

inactivity_label = tk.Label(root, text="", font=("Arial", 12), fg="red")
inactivity_label.pack(pady=5)

inactivity_counter = [30]
btn_run_pressed = [False]

def update_inactivity():
    if btn_run_pressed[0]:
        inactivity_label.config(text="")
        return
    if inactivity_counter[0] > 0:
        inactivity_label.config(
            text=f"Sin actividad: ejecutando automáticamente en {inactivity_counter[0]} segundos..."
        )
        inactivity_counter[0] -= 1
        root.after(1000, update_inactivity)
    else:
        inactivity_label.config(text="Ejecutando automáticamente ahora por inactividad.")
        auto_run()

def auto_run():
    btn_run_pressed[0] = True
    target = entry_target.get().strip()
    params = entry_params.get().strip()
    if not target:
        inactivity_label.config(text="No hay objetivo para ejecutar automáticamente.")
        return
    import re
    results = []
    # Detecta si es IP
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        results.append("=== Geolocalizar IP ===\n" + geolocate_ip(target))
        results.append("=== Whois ===\n" + run_whois_lookup(target))
        results.append("=== Ping ===\n" + run_ping(target))
        results.append("=== Traceroute ===\n" + run_traceroute(target))
        results.append("=== DNS Lookup ===\n" + run_dns_lookup(target))
        nmap_params_list = ["-F", "-A", "-Pn", "-sS", "-O", "-sV"]
        for nmap_params in nmap_params_list:
            results.append(f"=== Nmap ({nmap_params}) ===\n" + run_nmap_scan(target, nmap_params))
        results.append("=== Buscar IP en AbuseIPDB ===\n" + search_abuseipdb_ip(target))
    else:
        # Asume usuario/correo/dominio
        results.append("=== OSINT usuario/correo/localidad ===\n" + osint_user_info(target))
        results.append("=== Buscar usuario en GitHub ===\n" + search_github_user(target))
        results.append("=== Buscar usuario en Twitter ===\n" + search_twitter_user(target))
        results.append("=== Buscar usuario en Instagram ===\n" + search_instagram_user(target))
        results.append("=== Buscar usuario en Facebook ===\n" + search_facebook_user(target))
        results.append("=== Buscar email en HaveIBeenPwned ===\n" + search_hibp_email(target))
        results.append("=== Buscar dominio en VirusTotal ===\n" + search_virustotal_domain(target))
        results.append("=== Buscar dominio en SSL Labs ===\n" + search_ssllabs_domain(target))
        results.append("=== Buscar dominio en ThreatCrowd ===\n" + search_threatcrowd_domain(target))
        results.append("=== Buscar dominio en crt.sh ===\n" + search_crtsh_domain(target))
        results.append("=== Buscar dominio en SecurityTrails ===\n" + search_securitytrails_domain(target))
        results.append("=== Buscar dominio en Robtex ===\n" + search_robtex_domain(target))
        results.append("=== Buscar usuario en Roblox ===\n" + search_roblox_user(target))
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, "\n\n".join(results))

def on_run():
    btn_run_pressed[0] = True
    inactivity_label.config(text="")
    target = entry_target.get().strip()
    params = entry_params.get().strip()
    if not target:
        messagebox.showwarning("Advertencia", "Introduce un objetivo (IP, dominio, usuario, email, etc).")
        return
    import re
    results = []
    # Detecta si es IP
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        results.append("=== Geolocalizar IP ===\n" + geolocate_ip(target))
        results.append("=== Whois ===\n" + run_whois_lookup(target))
        results.append("=== Ping ===\n" + run_ping(target))
        results.append("=== Traceroute ===\n" + run_traceroute(target))
        results.append("=== DNS Lookup ===\n" + run_dns_lookup(target))
        nmap_params_list = ["-F", "-A", "-Pn", "-sS", "-O", "-sV"]
        for nmap_params in nmap_params_list:
            results.append(f"=== Nmap ({nmap_params}) ===\n" + run_nmap_scan(target, nmap_params))
        results.append("=== Buscar IP en AbuseIPDB ===\n" + search_abuseipdb_ip(target))
    elif re.match(r"^\+\d{7,15}$", target):
        results.append("=== Geolocalizar teléfono ===\n" + geolocate_phone(target))
    else:
        # Asume usuario/correo/dominio
        results.append("=== OSINT usuario/correo/localidad ===\n" + osint_user_info(target))
        results.append("=== Buscar usuario en GitHub ===\n" + search_github_user(target))
        results.append("=== Buscar usuario en Twitter ===\n" + search_twitter_user(target))
        results.append("=== Buscar usuario en Instagram ===\n" + search_instagram_user(target))
        results.append("=== Buscar usuario en Facebook ===\n" + search_facebook_user(target))
        results.append("=== Buscar email en HaveIBeenPwned ===\n" + search_hibp_email(target))
        results.append("=== Buscar dominio en VirusTotal ===\n" + search_virustotal_domain(target))
        results.append("=== Buscar dominio en SSL Labs ===\n" + search_ssllabs_domain(target))
        results.append("=== Buscar dominio en ThreatCrowd ===\n" + search_threatcrowd_domain(target))
        results.append("=== Buscar dominio en crt.sh ===\n" + search_crtsh_domain(target))
        results.append("=== Buscar dominio en SecurityTrails ===\n" + search_securitytrails_domain(target))
        results.append("=== Buscar dominio en Robtex ===\n" + search_robtex_domain(target))
        results.append("=== Buscar usuario en Roblox ===\n" + search_roblox_user(tarjet))

    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, "\n\n".join(results))

btn_run.config(command=on_run)

def set_theme(theme):
    if theme == "Oscuro":
        bg = "#222"
        fg = "#eee"
        entry_bg = "#333"
        entry_fg = "#eee"
        btn_bg = "#333"
        btn_fg = "#eee"
        label_fg = "#eee"
        led_color = None
    elif theme == "Claro":
        bg = "#f5f5f5"
        fg = "#222"
        entry_bg = "#fff"
        entry_fg = "#222"
        btn_bg = "#e0e0e0"
        btn_fg = "#222"
        label_fg = "#222"
        led_color = None
    elif theme == "Light":
        bg = "#222"
        fg = "#eee"
        entry_bg = "#333"
        entry_fg = "#eee"
        btn_bg = "#333"
        btn_fg = "#eee"
        label_fg = "#eee"
        led_color = "#0ff"
    else:
        return

    # Fondo principal
    root.configure(bg=bg)
    frame_top.configure(bg=bg)
    theme_frame.configure(bg=bg)
    label_tools.configure(bg=bg, fg=label_fg)
    inactivity_label.configure(bg=bg, fg="red")

    # Entradas y botones
    for widget in frame_top.winfo_children():
        # Solo cambia color si es tk.Entry
        if type(widget) == tk.Entry:
            widget.configure(bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
        elif type(widget) == tk.Label:
            widget.configure(bg=bg, fg=label_fg)
        elif type(widget) == tk.Button:
            widget.configure(bg=btn_bg, fg=btn_fg)
        # ttk widgets no se configuran aquí

    for widget in theme_frame.winfo_children():
        if type(widget) == tk.Label:
            widget.configure(bg=bg, fg=label_fg)
        # ttk widgets no se configuran aquí

    for btn in osint_buttons:
        btn.configure(bg=btn_bg, fg=btn_fg, activebackground=btn_bg, activeforeground=btn_fg)

    # Fondo y borde del área de resultados
    text_output.configure(bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
    if led_color and theme == "Light":
        text_output.configure(highlightbackground=led_color, highlightthickness=4)
    else:
        text_output.configure(highlightthickness=0)

    # Estilo para ttk.Combobox
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TCombobox", fieldbackground=entry_bg, background=entry_bg, foreground=entry_fg)

# Al final de la configuración de widgets, llama a set_theme con el valor actual
set_theme(theme_var.get())

update_inactivity()

root.mainloop()