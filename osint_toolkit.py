# -*- coding: utf-8 -*-
"""
Impawnd-OSINT v2.0 – GUI OSINT & Vuln Scanners
Diseño cyber-neón + advertencia legal + escáneres de vuln
Respetuoso con la opción elegida
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import webbrowser
import time
import threading
import re
import requests

# ---------- Advertencia legal (pop-up al iniciar) ----------
LEGAL_TEXT = (
    "🛡️ USO ÉTICO Y LEGAL\n\n"
    "Esta herramienta solo debe utilizarse sobre objetivos que tengas "
    "permiso explícito (pentesting autorizado, investigación personal o educativa). "
    "El autor no se hace responsable de un mal uso.\n\n"
    "¿Aceptas y continúas?"
)

# ---------- Herramientas externas (solo enlaces) ----------
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

# ---------- Funciones internas ----------
FUNC_TOOLS = [
    "Nmap (escaneo rápido)",
    "Geolocalizar IP",
    "Geolocalizar teléfono",
    "Hydra (demo)",
    "SQLMap (demo)",
    "Whois",
    "Ping",
    "Traceroute",
    "DNS Lookup",
    "WhatWeb (demo)",
    "Dirb (demo)",
    "Nikto (demo)",
    "WPScan (demo)",
    "Sublist3r (demo)",
    "Amass (demo)",
    "theHarvester (demo)",
    "Nessus (help)",
    "OpenVAS (help)",
    "Nexpose (help)",
    "Burp Suite (help)",
    "OWASP ZAP (help)",
    "OSINT usuario/correo/localidad",
    "Buscar usuario en GitHub",
    "Buscar usuario en Twitter",
    "Buscar usuario en Instagram",
    "Buscar usuario en Facebook",
    "Buscar usuario en Roblox",
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

def run_cmd(cmd, timeout=10):
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return result
    except subprocess.TimeoutExpired:
        return f"{' '.join(cmd)}: tiempo agotado ({timeout} s)."
    except Exception as e:
        return f"Error ejecutando {' '.join(cmd)}: {str(e)}"

# ---------- Comandos clásicos ----------
def run_nmap_scan(target, params):
    return run_cmd(['nmap'] + params.split() + [target])

def run_whois_lookup(target):
    return run_cmd(['whois', target])

def run_ping(target):
    return run_cmd(['ping', '-c', '4', target])

def run_traceroute(target):
    return run_cmd(['traceroute', target])

def run_dns_lookup(target):
    return run_cmd(['nslookup', target])

# ---------- Web / Vuln scanners (demo) ----------
def run_whatweb(target):
    return run_cmd(['whatweb', '--help'])

def run_dirb(target):
    return run_cmd(['dirb'], timeout=5)

def run_nikto(target):
    return run_cmd(['nikto', '-Help'])

def run_wpscan(target):
    return run_cmd(['wpscan', '--help'])

def run_sublistr(target):
    return run_cmd(['sublist3r', '-h'])

def run_amass(target):
    return run_cmd(['amass', '-h'])

def run_theharvester(target):
    return run_cmd(['theHarvester', '-h'])

# ---------- Escáneres de vulnerabilidades (solo ayuda) ----------
def run_nessus_help(target):
    return "Nessus: abre el enlace oficial → https://www.tenable.com/products/nessus"

def run_openvas_help(target):
    return "OpenVAS: abre el enlace oficial → https://www.greenbone.net/en/openvas/"

def run_nexpose_help(target):
    return "Nexpose: abre el enlace oficial → https://www.rapid7.com/products/nexpose/"

def run_burp_help(target):
    return "Burp Suite: abre el enlace oficial → https://portswigger.net/burp"

def run_zap_help(target):
    return "OWASP ZAP: abre el enlace oficial → https://www.zaproxy.org/"

# ---------- Hydra / SQLMap (demo) ----------
def run_hydra(target, params):
    return run_cmd(['hydra', '-h'])

def run_sqlmap(target, params):
    return run_cmd(['sqlmap', '--help'])

# ---------- IP & Phone ----------
def geolocate_ip(ip):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(f"https://ipapi.co/{ip}/json/", headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            lat, lon = data.get('latitude'), data.get('longitude')
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
            if lat and lon:
                def open_earth():
                    time.sleep(5)
                    webbrowser.open(f"https://earth.google.com/web/search/{lat},{lon}")
                threading.Thread(target=open_earth, daemon=True).start()
                info += f"\nGoogle Earth se abrirá en 5 s: https://earth.google.com/web/search/{lat},{lon}\n"
            return info
        else:
            return f"Error IP: {resp.status_code}"
    except Exception as e:
        return f"Error geolocating IP: {str(e)}"

def geolocate_phone(phone):
    API_KEY = "ef9d9159f8b256ad18d6752773d4e6a3"  # demo
    try:
        resp = requests.get(f"http://apilayer.net/api/validate?access_key={API_KEY}&number={phone}&format=1", timeout=10)
        data = resp.json()
        if data.get("valid"):
            return (
                f"Número: {data.get('local_format')}\n"
                f"País: {data.get('country_name')} ({data.get('country_code')})\n"
                f"Ubicación: {data.get('location')}\n"
                f"Operador: {data.get('carrier')}\n"
                f"Línea: {data.get('line_type')}\n"
            )
        else:
            return "Número no válido o no encontrado."
    except Exception as e:
        return f"Error geolocating phone: {str(e)}"

# ---------- OSINT usuario ----------
def osint_user_info(query):
    info = f"Resultados OSINT para: {query}\n\n"
    # GitHub
    try:
        r = requests.get(f"https://api.github.com/users/{query}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            info += f"[GitHub]\nNombre: {data.get('name')}\nBio: {data.get('bio')}\nRepos: {data.get('public_repos')}\nSeguidores: {data.get('followers')}\nURL: {data.get('html_url')}\n\n"
        else:
            info += "[GitHub] No encontrado.\n\n"
    except Exception as e:
        info += f"[GitHub] Error: {e}\n\n"

    # URLs rápidas
    for red, url in [("Twitter", f"https://twitter.com/{query}"),
                     ("Instagram", f"https://instagram.com/{query}"),
                     ("Facebook", f"https://facebook.com/{query}"),
                     ("HaveIBeenPwned", f"https://haveibeenpwned.com/account/{query}"),
                     ("Hunter", f"https://hunter.io/search/{query}"),
                     ("Roblox", f"https://www.roblox.com/users/{query}/profile")]:
        info += f"[{red}] {url}\n"

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query):
        info += "\n[Geolocalización IP]\n" + geolocate_ip(query)

    return info

# ---------- GUI ----------
root = tk.Tk()
root.title("🕵️‍♂️ Impawnd-OSINT v3.0 – Cyber-Neón")
root.geometry("900x750")
root.configure(bg="#0d0d0d")

# ---------- Banner legal ----------
if not messagebox.askyesno("⚖️ Advertencia legal", LEGAL_TEXT):
    root.destroy()
    exit()

# ---------- Estilos ----------
style = ttk.Style()
style.theme_use('clam')
style.configure("TCombobox", fieldbackground="#1a1a1a", background="#1a1a1a", foreground="#0ff", arrowcolor="#0ff")
style.map("TCombobox", fieldbackground=[("readonly", "#1a1a1a")], foreground=[("readonly", "#0ff")])

frame_top = tk.Frame(root, bg="#0d0d0d")
frame_top.pack(pady=15)

tk.Label(frame_top, text="🛠️ Herramienta:", font=("Arial", 12, "bold"), fg="#0ff", bg="#0d0d0d").pack(side=tk.LEFT, padx=5)
combo_tools = ttk.Combobox(frame_top, values=FUNC_TOOLS, state="readonly", width=35, style="TCombobox")
combo_tools.current(0)
combo_tools.pack(side=tk.LEFT, padx=5)

tk.Label(frame_top, text="🎯 Objetivo:", font=("Arial", 12, "bold"), fg="#0ff", bg="#0d0d0d").pack(side=tk.LEFT, padx=5)
entry_target = tk.Entry(frame_top, width=30, bg="#1a1a1a", fg="#0ff", insertbackground="#0ff", bd=0, highlightthickness=1, highlightbackground="#0ff")
entry_target.pack(side=tk.LEFT, padx=5)

tk.Label(frame_top, text="🔧 Parámetros:", font=("Arial", 12, "bold"), fg="#0ff", bg="#0d0d0d").pack(side=tk.LEFT, padx=5)
entry_params = tk.Entry(frame_top, width=20, bg="#1a1a1a", fg="#0ff", insertbackground="#0ff", bd=0, highlightthickness=1, highlightbackground="#0ff")
entry_params.insert(0, "-F")
entry_params.pack(side=tk.LEFT, padx=5)

btn_run = tk.Button(frame_top, text="▶ EJECUTAR", bg="#0ff", fg="#000", font=("Arial", 10, "bold"), bd=0, activebackground="#fff", activeforeground="#000")
btn_run.pack(side=tk.LEFT, padx=10)

# ---------- Área de resultados ----------
text_output = scrolledtext.ScrolledText(root, width=110, height=22, bg="#0d0d0d", fg="#0ff", insertbackground="#0ff", bd=0, highlightthickness=1, highlightbackground="#0ff", font=("Consolas", 10))
text_output.pack(pady=10)

label_tools = tk.Label(root, text="🔍 Herramientas OSINT externas", font=("Arial", 14, "bold"), fg="#0ff", bg="#0d0d0d")
label_tools.pack(pady=10)

osint_buttons = []
for name, url in OSINT_TOOLS:
    btn = tk.Button(root, text=name, width=45, bg="#1a1a1a", fg="#0ff", bd=0, activebackground="#0ff", activeforeground="#000", command=lambda u=url: open_tool(u))
    btn.pack(pady=2)
    osint_buttons.append(btn)

inactivity_label = tk.Label(root, text="", font=("Arial", 11), fg="#0ff", bg="#0d0d0d")
inactivity_label.pack(pady=5)

inactivity_counter = [30]
btn_run_pressed = [False]

def update_inactivity():
    if btn_run_pressed[0]:
        inactivity_label.config(text="")
        return
    if inactivity_counter[0] > 0:
        inactivity_label.config(text=f"⏳ Sin actividad: auto-ejecución en {inactivity_counter[0]} s")
        inactivity_counter[0] -= 1
        root.after(1000, update_inactivity)
    else:
        inactivity_label.config(text="🔥 Ejecutando automáticamente ahora por inactividad.")
        auto_run()

def auto_run():
    btn_run_pressed[0] = True
    target = entry_target.get().strip()
    params = entry_params.get().strip()
    if not target:
        inactivity_label.config(text="❌ No hay objetivo para ejecutar automáticamente.")
        return
    import re
    results = []
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
    tool = combo_tools.get()
    if not tool:
        messagebox.showwarning("Advertencia", "Selecciona una herramienta.")
        return
    import re
    results = []

    # Mapeo limpio: cada herramienta → su función
    func_map = {
        "Nmap (escaneo rápido)": lambda: "=== Nmap ===\n" + run_nmap_scan(target, params),
        "Geolocalizar IP": lambda: "=== Geolocalizar IP ===\n" + geolocate_ip(target),
        "Geolocalizar teléfono": lambda: "=== Geolocalizar teléfono ===\n" + geolocate_phone(target),
        "Whois": lambda: "=== Whois ===\n" + run_whois_lookup(target),
        "Ping": lambda: "=== Ping ===\n" + run_ping(target),
        "Traceroute": lambda: "=== Traceroute ===\n" + run_traceroute(target),
        "DNS Lookup": lambda: "=== DNS Lookup ===\n" + run_dns_lookup(target),
        "WhatWeb (demo)": lambda: "=== WhatWeb ===\n" + run_whatweb(target),
        "Dirb (demo)": lambda: "=== Dirb ===\n" + run_dirb(target),
        "Nikto (demo)": lambda: "=== Nikto ===\n" + run_nikto(target),
        "WPScan (demo)": lambda: "=== WPScan ===\n" + run_wpscan(target),
        "Sublist3r (demo)": lambda: "=== Sublist3r ===\n" + run_sublistr(target),
        "Amass (demo)": lambda: "=== Amass ===\n" + run_amass(target),
        "theHarvester (demo)": lambda: "=== theHarvester ===\n" + run_theharvester(target),
        "Nessus (help)": lambda: run_nessus_help(target),
        "OpenVAS (help)": lambda: run_openvas_help(target),
        "Nexpose (help)": lambda: run_nexpose_help(target),
        "Burp Suite (help)": lambda: run_burp_help(target),
        "OWASP ZAP (help)": lambda: run_zap_help(target),
        "OSINT usuario/correo/localidad": lambda: "=== OSINT usuario ===\n" + osint_user_info(target),
        "Buscar usuario en GitHub": lambda: search_github_user(target),
        "Buscar usuario en Twitter": lambda: search_twitter_user(target),
        "Buscar usuario en Instagram": lambda: search_instagram_user(target),
        "Buscar usuario en Facebook": lambda: search_facebook_user(target),
        "Buscar usuario en Roblox": lambda: search_roblox_user(target),
        "Buscar email en HaveIBeenPwned": lambda: search_hibp_email(target),
        "Buscar dominio en VirusTotal": lambda: search_virustotal_domain(target),
        "Buscar IP en AbuseIPDB": lambda: search_abuseipdb_ip(target),
        "Buscar dominio en SSL Labs": lambda: search_ssllabs_domain(target),
        "Buscar dominio en ThreatCrowd": lambda: search_threatcrowd_domain(target),
        "Buscar dominio en crt.sh": lambda: search_crtsh_domain(target),
        "Buscar dominio en SecurityTrails": lambda: search_securitytrails_domain(target),
        "Buscar dominio en Robtex": lambda: search_robtex_domain(target),
        "Hydra (demo)": lambda: "=== Hydra ===\n" + run_hydra(target, params),
        "SQLMap (demo)": lambda: "=== SQLMap ===\n" + run_sqlmap(target, params),
    }

    if tool in func_map:
        results.append(func_map[tool]())
    else:
        results.append("Herramienta no implementada.")

    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, "\n\n".join(results))

btn_run.config(command=on_run)

# ---------- Temas ----------
def set_theme(theme):
    bg, fg, entry_bg, entry_fg, btn_bg, btn_fg, label_fg, led_color = (
        ("#0d0d0d", "#0ff", "#1a1a1a", "#0ff", "#1a1a1a", "#0ff", "#0ff", None) if theme == "Oscuro" else
        ("#f5f5f5", "#222", "#fff", "#222", "#e0e0e0", "#222", "#222", None) if theme == "Claro" else
        ("#0d0d0d", "#0ff", "#1a1a1a", "#0ff", "#1a1a1a", "#0ff", "#0ff", "#0ff")
    )
    root.configure(bg=bg)
    frame_top.configure(bg=bg)
    theme_frame.configure(bg=bg)
    label_tools.configure(bg=bg, fg=label_fg)
    inactivity_label.configure(bg=bg, fg=label_fg)
    for widget in frame_top.winfo_children():
        if type(widget) == tk.Entry:
            widget.configure(bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
        elif type(widget) == tk.Label:
            widget.configure(bg=bg, fg=label_fg)
        elif type(widget) == tk.Button:
            widget.configure(bg=btn_bg, fg=btn_fg)
    for widget in theme_frame.winfo_children():
        if type(widget) == tk.Label:
            widget.configure(bg=bg, fg=label_fg)
    for btn in osint_buttons:
        btn.configure(bg=btn_bg, fg=btn_fg, activebackground=btn_bg, activeforeground=btn_fg)
    text_output.configure(bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
    if led_color and theme == "Light":
        text_output.configure(highlightbackground=led_color, highlightthickness=4)
    else:
        text_output.configure(highlightthickness=0)
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TCombobox", fieldbackground=entry_bg, background=entry_bg, foreground=entry_fg)

# ---------- Selector de tema ----------
theme_frame = tk.Frame(root, bg="#0d0d0d")
theme_frame.pack(pady=5)

tk.Label(theme_frame, text="🎨 Tema:", font=("Arial", 12, "bold"), fg="#0ff", bg="#0d0d0d").pack(side=tk.LEFT, padx=5)
theme_var = tk.StringVar(value="Oscuro")
theme_selector = ttk.Combobox(theme_frame, textvariable=theme_var, values=["Oscuro", "Claro", "Light"], state="readonly", width=10, style="TCombobox")
theme_selector.current(0)
theme_selector.pack(side=tk.LEFT, padx=5)
theme_selector.bind("<<ComboboxSelected>>", lambda e: set_theme(theme_var.get()))

# ---------- Funciones ficticias para evitar errores ----------
# (Puedes completarlas luego con peticiones reales)
def search_github_user(user): return f"https://github.com/{user}"
def search_twitter_user(user): return f"https://twitter.com/{user}"
def search_instagram_user(user): return f"https://instagram.com/{user}"
def search_facebook_user(user): return f"https://facebook.com/{user}"
def search_roblox_user(user): return f"https://www.roblox.com/users/{user}/profile"
def search_hibp_email(email): return f"https://haveibeenpwned.com/account/{email}"
def search_virustotal_domain(domain): return f"https://www.virustotal.com/gui/domain/{domain}"
def search_abuseipdb_ip(ip): return f"https://www.abuseipdb.com/check/{ip}"
def search_ssllabs_domain(domain): return f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}"
def search_threatcrowd_domain(domain): return f"https://www.threatcrowd.org/domain.php?domain={domain}"
def search_crtsh_domain(domain): return f"https://crt.sh/?q={domain}"
def search_securitytrails_domain(domain): return f"https://securitytrails.com/domain/{domain}"
def search_robtex_domain(domain): return f"https://www.robtex.com/dns-lookup/{domain}"

# ---------- Aplicar tema inicial y arrancar ----------
set_theme(theme_var.get())
update_inactivity()
root.mainloop()
