# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import webbrowser
import threading
import requests

LEGAL_TEXT = (
    "🛡️ USO ÉTICO Y LEGAL\n\n"
    "Esta herramienta solo debe utilizarse con permiso explícito. "
    "El autor no se hace responsable del mal uso."
)

class OSINTApp(tk.Tk):
    def __init__(self):
        super().__init__()
        if not messagebox.askyesno("⚖️ Advertencia legal", LEGAL_TEXT):
            self.destroy()
            return
        self.title("🕵️‍♂️ Impawnd-OSINT v4.0 – Rediseño")
        self.geometry("1000x800")
        self.configure(bg="#0d0d0d")
        self.init_style()
        self.create_widgets()
        self.set_theme("Cyber-Neón")

    def init_style(self):
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        # Definir estilos para el tema Cyber-Neón
        self.style.configure("Cyber.TFrame", background="#0d0d0d")
        self.style.configure("Cyber.TLabel", background="#0d0d0d", foreground="#0ff", font=("Arial", 12, "bold"))
        self.style.configure("Cyber.TButton", background="#1a1a1a", foreground="#0ff", font=("Arial", 10, "bold"), borderwidth=0)
        self.style.map("Cyber.TButton", background=[('active', '#0ff')], foreground=[('active', '#000')])
        self.style.configure("Cyber.TEntry", fieldbackground="#1a1a1a", foreground="#0ff", insertbackground="#0ff", borderwidth=0)
        self.style.configure("Cyber.TCombobox", fieldbackground="#1a1a1a", background="#1a1a1a", foreground="#0ff", arrowcolor="#0ff")
        self.style.configure("Cyber.TNotebook", background="#0d0d0d", borderwidth=0)
        self.style.configure("Cyber.TNotebook.Tab", background="#1a1a1a", foreground="#0ff", padding=[10, 5], font=("Arial", 10, "bold"))
        self.style.map("Cyber.TNotebook.Tab", background=[("selected", "#0ff")], foreground=[("selected", "#000")])

    def create_widgets(self):
        main_frame = ttk.Frame(self, style="Cyber.TFrame")
        main_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # --- Controles Superiores ---
        controls_frame = ttk.Frame(main_frame, style="Cyber.TFrame")
        controls_frame.pack(fill="x", pady=5)

        ttk.Label(controls_frame, text="🎯 Objetivo:", style="Cyber.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        self.entry_target = ttk.Entry(controls_frame, width=40, style="Cyber.TEntry")
        self.entry_target.pack(side=tk.LEFT, expand=True, fill="x", padx=5)

        self.btn_run = ttk.Button(controls_frame, text="▶ EJECUTAR", style="Cyber.TButton", command=self.on_run)
        self.btn_run.pack(side=tk.LEFT, padx=5)

        # --- Notebook para Pestañas ---
        notebook = ttk.Notebook(main_frame, style="Cyber.TNotebook")
        notebook.pack(expand=True, fill="both", pady=10)

        self.tool_tabs = {}
        self.create_tab(notebook, "🌐 Red", self.get_network_tools())
        self.create_tab(notebook, "🕵️ OSINT", self.get_osint_tools())
        self.create_tab(notebook, "🔗 Web", self.get_web_tools())

        # --- Área de Resultados ---
        self.text_output = scrolledtext.ScrolledText(main_frame, bg="#0d0d0d", fg="#0ff", font=("Consolas", 11), bd=0, highlightthickness=0)
        self.text_output.pack(expand=True, fill="both")

    def create_tab(self, notebook, tab_name, tools):
        tab = ttk.Frame(notebook, style="Cyber.TFrame")
        notebook.add(tab, text=tab_name)

        self.tool_tabs[tab_name] = {}
        for tool_name, tool_info in tools.items():
            frame = ttk.Frame(tab, style="Cyber.TFrame", padding=5)
            frame.pack(fill="x")

            var = tk.BooleanVar(value=tool_info.get("default", False))
            chk = ttk.Checkbutton(frame, text=tool_name, variable=var, style="Cyber.TCheckbutton")
            chk.pack(side=tk.LEFT)
            self.tool_tabs[tab_name][tool_name] = {"var": var, "params": tool_info.get("params")}

    def on_run(self):
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showwarning("Advertencia", "Introduce un objetivo.")
            return

        self.text_output.delete(1.0, tk.END)
        self.text_output.insert(tk.END, f"--- Ejecutando análisis sobre {target} ---\n\n")

        for tab_name, tools in self.tool_tabs.items():
            for tool_name, tool_data in tools.items():
                if tool_data["var"].get():
                    params = tool_data["params"]
                    threading.Thread(target=self.execute_tool, args=(tool_name, target, params), daemon=True).start()

    def execute_tool(self, tool, target, params):
        self.update_output(f"--- {tool} ---")
        try:
            func = self.get_tool_function(tool)
            output = func(target, params)
            self.update_output(output)
        except Exception as e:
            self.update_output(f"Error ejecutando {tool}: {e}")

    def update_output(self, message):
        self.after(0, lambda: self.text_output.insert(tk.END, f"{message}\n\n"))

    def set_theme(self, theme_name):
        # Por ahora, solo tenemos Cyber-Neón
        pass

    # --- Definiciones de Herramientas ---
    def get_network_tools(self):
        return {
            "Ping": {"params": None, "default": True},
            "Whois": {"params": None},
            "Nmap - Escaneo Rápido": {"params": "-F -T4"},
            "Nmap - Escaneo Intenso": {"params": "-A -T4"},
            "Traceroute": {"params": None}
        }

    def get_osint_tools(self):
        return {
            "Geolocalizar IP": {"params": None, "default": True},
            "Buscar en Shodan": {"params": "https://www.shodan.io/host/{target}"}
        }

    def get_web_tools(self):
        return {
            "WhatWeb": {"params": None},
            "SSL Scan": {"params": "https://www.ssllabs.com/ssltest/analyze.html?d={target}"}
        }

    # --- Lógica de Comandos ---
    def get_tool_function(self, tool_name):
        return {
            "Ping": self.run_ping,
            "Whois": self.run_whois,
            "Nmap - Escaneo Rápido": self.run_nmap,
            "Nmap - Escaneo Intenso": self.run_nmap,
            "Traceroute": self.run_traceroute,
            "Geolocalizar IP": self.geolocate_ip,
            "Buscar en Shodan": self.open_web,
            "WhatWeb": self.run_whatweb,
            "SSL Scan": self.open_web
        }.get(tool_name)

    def run_command(self, cmd_list):
        try:
            return subprocess.check_output(cmd_list, stderr=subprocess.STDOUT, text=True, timeout=30)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
            return f"Error: {e}"

    def run_ping(self, target, params): return self.run_command(['ping', '-c', '4', target])
    def run_whois(self, target, params): return self.run_command(['whois', target])
    def run_nmap(self, target, params): return self.run_command(['nmap'] + params.split() + [target])
    def run_traceroute(self, target, params): return self.run_command(['traceroute', target])
    def run_whatweb(self, target, params): return self.run_command(['whatweb', target])

    def geolocate_ip(self, ip, params):
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
            r.raise_for_status()
            data = r.json()
            return "\n".join([f"{k.capitalize()}: {v}" for k, v in data.items()])
        except requests.RequestException as e:
            return f"Error de red: {e}"

    def open_web(self, target, url_template):
        url = url_template.format(target=target)
        webbrowser.open(url)
        return f"Abriendo: {url}"

if __name__ == "__main__":
    app = OSINTApp()
    if app.winfo_exists():
        app.mainloop()