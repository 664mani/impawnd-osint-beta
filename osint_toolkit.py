# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import webbrowser
import threading
import requests
import json
from datetime import datetime

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

        self.title("🕵️‍♂️ Impawnd-OSINT v5.0 – Edición Mejorada")
        self.geometry("1100x850")
        self.configure(bg="#0d0d0d")

        self.init_style()
        self.create_widgets()

    def init_style(self):
        self.style = ttk.Style(self)
        self.style.theme_use('clam')

        # --- Estilos Cyber-Neón ---
        self.style.configure("Cyber.TFrame", background="#0d0d0d")
        self.style.configure("Cyber.TLabel", background="#0d0d0d", foreground="#0ff", font=("Arial", 12, "bold"))
        self.style.configure("Title.TLabel", background="#0d0d0d", foreground="#0ff", font=("Consolas", 20, "bold"))
        self.style.configure("Cyber.TButton", background="#1a1a1a", foreground="#0ff", font=("Arial", 10, "bold"), borderwidth=0, padding=5)
        self.style.map("Cyber.TButton", background=[('active', '#0ff')], foreground=[('active', '#000')])
        self.style.configure("Cyber.TEntry", fieldbackground="#1a1a1a", foreground="#0ff", insertbackground="#0ff", borderwidth=0)
        self.style.configure("Cyber.TCheckbutton", background="#0d0d0d", foreground="#999", indicatorcolor="#0ff", font=("Arial", 11))
        self.style.map("Cyber.TCheckbutton", foreground=[('active', '#0ff')])
        self.style.configure("Cyber.TNotebook", background="#0d0d0d", borderwidth=0)
        self.style.configure("Cyber.TNotebook.Tab", background="#1a1a1a", foreground="#0ff", padding=[15, 5], font=("Arial", 11, "bold"))
        self.style.map("Cyber.TNotebook.Tab", background=[("selected", "#0ff")], foreground=[("selected", "#000")])

    def create_widgets(self):
        main_frame = ttk.Frame(self, style="Cyber.TFrame")
        main_frame.pack(expand=True, fill="both", padx=15, pady=15)

        # --- Logo/Título ---
        ttk.Label(main_frame, text="[ Impawnd-OSINT ]", style="Title.TLabel").pack(pady=(0, 15))

        # --- Controles Superiores ---
        controls_frame = ttk.Frame(main_frame, style="Cyber.TFrame")
        controls_frame.pack(fill="x", pady=5)

        ttk.Label(controls_frame, text="🎯 Objetivo:", style="Cyber.TLabel").pack(side=tk.LEFT, padx=(0, 5))
        self.entry_target = ttk.Entry(controls_frame, width=40, style="Cyber.TEntry", font=("Consolas", 12))
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
        self.create_settings_tab(notebook)
        self.create_about_tab(notebook)

        # --- Área de Resultados ---
        results_frame = ttk.Frame(main_frame, style="Cyber.TFrame")
        results_frame.pack(expand=True, fill="both")

        self.text_output = scrolledtext.ScrolledText(results_frame, bg="#000", fg="#0ff", font=("Consolas", 11), bd=0, highlightthickness=0, wrap=tk.WORD)
        self.text_output.pack(expand=True, fill="both", side=tk.LEFT)

        # --- Botón de Exportar ---
        self.btn_export = ttk.Button(results_frame, text="Exportar\nResultados", style="Cyber.TButton", command=self.export_results)
        self.btn_export.pack(side=tk.RIGHT, padx=10, fill="y")


    def create_tab(self, notebook, tab_name, tools):
        tab = ttk.Frame(notebook, style="Cyber.TFrame")
        notebook.add(tab, text=tab_name)

        self.tool_tabs[tab_name] = {}
        for tool_name, tool_info in tools.items():
            frame = ttk.Frame(tab, style="Cyber.TFrame", padding=5)
            frame.pack(fill="x")

            var = tk.BooleanVar(value=tool_info.get("default", False))
            # Usar el nombre con el icono en el Checkbutton
            chk = ttk.Checkbutton(frame, text=tool_info["icon"] + " " + tool_name, variable=var, style="Cyber.TCheckbutton")
            chk.pack(side=tk.LEFT)
            self.tool_tabs[tab_name][tool_name] = {"var": var, "params": tool_info.get("params"), "func": tool_info["func"]}

    def on_run(self):
        target = self.entry_target.get().strip()
        if not target:
            messagebox.showwarning("Advertencia", "Introduce un objetivo.")
            return

        self.text_output.delete(1.0, tk.END)
        self.update_output(f"--- Análisis iniciado sobre [ {target} ] a las {datetime.now().strftime('%H:%M:%S')} ---", "title")

        for tab_name, tools in self.tool_tabs.items():
            for tool_name, tool_data in tools.items():
                if tool_data["var"].get():
                    params = tool_data["params"]
                    func = tool_data["func"]
                    # Ejecutar en un hilo para no bloquear la GUI
                    threading.Thread(target=self.execute_tool, args=(tool_name, func, target, params), daemon=True).start()

    def execute_tool(self, tool_name, func, target, params):
        self.update_output(f"Ejecutando: {tool_name}...", "header")
        try:
            output = func(target, params)
            self.update_output(output, "result")
        except Exception as e:
            self.update_output(f"Error en {tool_name}: {e}", "error")

    def update_output(self, message, tag=None):
        def _update():
            self.text_output.configure(state='normal')
            if tag == "title":
                self.text_output.insert(tk.END, f"{message}\n\n", "title_tag")
            elif tag == "header":
                self.text_output.insert(tk.END, f"--- {message} ---\n", "header_tag")
            elif tag == "result":
                self.text_output.insert(tk.END, f"{message}\n\n", "result_tag")
            elif tag == "error":
                self.text_output.insert(tk.END, f"❌ {message}\n\n", "error_tag")
            else:
                self.text_output.insert(tk.END, f"{message}\n")

            self.text_output.configure(state='disabled')
            self.text_output.see(tk.END)

        # Configurar etiquetas de estilo si no existen
        if not "title_tag" in self.text_output.tag_names():
            self.text_output.tag_configure("title_tag", font=("Consolas", 14, "bold"), foreground="#fff")
            self.text_output.tag_configure("header_tag", font=("Consolas", 12, "italic"), foreground="#777")
            self.text_output.tag_configure("result_tag", font=("Consolas", 11), foreground="#0ff")
            self.text_output.tag_configure("error_tag", font=("Consolas", 11), foreground="#f00")

        self.after(0, _update)

    def export_results(self):
        content = self.text_output.get(1.0, tk.END)
        if not content.strip():
            messagebox.showwarning("Vacío", "No hay resultados para exportar.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Guardar resultados como..."
        )
        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Éxito", f"Resultados guardados en {filepath}")


    # --- Definiciones de Herramientas ---
    def get_network_tools(self):
        return {
            "Ping": {"icon": "📡", "params": None, "func": self.run_ping, "default": True},
            "Whois": {"icon": "👤", "params": None, "func": self.run_whois},
            "Nmap - Rápido": {"icon": "⚡", "params": "-F -T4", "func": self.run_nmap},
            "Nmap - Intenso": {"icon": "🔥", "params": "-A -T4", "func": self.run_nmap},
            "Traceroute": {"icon": "🗺️", "params": None, "func": self.run_traceroute}
        }

    def get_osint_tools(self):
        return {
            "Geolocalizar IP": {"icon": "📍", "params": None, "func": self.geolocate_ip, "default": True},
            "Geolocalizar Teléfono": {"icon": "📱", "params": None, "func": self.geolocate_phone},
            "Buscar en Shodan": {"icon": "🤖", "params": "https://www.shodan.io/host/{target}", "func": self.open_web}
        }

    def get_web_tools(self):
        return {
            "WhatWeb": {"icon": "🌐", "params": None, "func": self.run_whatweb},
            "SSL Scan": {"icon": "🔒", "params": "https://www.ssllabs.com/ssltest/analyze.html?d={target}", "func": self.open_web}
        }

    # --- Lógica de Comandos ---
    def run_command(self, cmd_list):
        try:
            cmd_list = [item for item in cmd_list if item] # Eliminar params vacíos
            return subprocess.check_output(cmd_list, stderr=subprocess.STDOUT, text=True, timeout=45)
        except FileNotFoundError:
            return f"Comando '{cmd_list[0]}' no encontrado. Asegúrate de que está instalado."
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            return f"Error: {e.output or e}"

    def run_ping(self, target, params): return self.run_command(['ping', '-c', '4', target])
    def run_whois(self, target, params): return self.run_command(['whois', target])
    def run_nmap(self, target, params): return self.run_command(['nmap'] + params.split() + [target])
    def run_traceroute(self, target, params): return self.run_command(['traceroute', target])
    def run_whatweb(self, target, params): return self.run_command(['whatweb', target])

    def geolocate_ip(self, ip, params):
        try:
            r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10, headers={'User-Agent': 'Impawnd-OSINT-Tool'})
            r.raise_for_status()
            data = r.json()
            # Formatear la salida de forma más limpia
            return "\n".join([f"{k.replace('_', ' ').capitalize():<15}: {v}" for k, v in data.items() if v])
        except requests.RequestException as e:
            return f"Error de red: {e}"

    def geolocate_phone(self, phone_number, params):
        api_key = self.numverify_api_key.get()
        if not api_key:
            return "Error: La clave API de Numverify no está configurada en Ajustes."

        try:
            url = f"http://apilayer.net/api/validate?access_key={api_key}&number={phone_number}&format=1"
            r = requests.get(url, timeout=10, headers={'User-Agent': 'Impawnd-OSINT-Tool'})
            r.raise_for_status()
            data = r.json()

            if not data.get("valid"):
                return "Número de teléfono no válido o no encontrado."

            return "\n".join([f"{k.replace('_', ' ').capitalize():<15}: {v}" for k, v in data.items() if v])
        except requests.RequestException as e:
            return f"Error de red: {e}"
        except Exception as e:
            return f"Error inesperado: {e}"

    def open_web(self, target, url_template):
        url = url_template.format(target=target)
        webbrowser.open(url)
        return f"Abriendo: {url}"

    def create_settings_tab(self, notebook):
        settings_tab = ttk.Frame(notebook, style="Cyber.TFrame", padding=20)
        notebook.add(settings_tab, text="⚙️ Ajustes")

        # API Key de Numverify
        ttk.Label(settings_tab, text="Clave API de Numverify:", style="Cyber.TLabel").pack(anchor="w")
        self.numverify_api_key = tk.StringVar()
        ttk.Entry(settings_tab, textvariable=self.numverify_api_key, width=50, style="Cyber.TEntry").pack(fill="x", pady=5)

        ttk.Button(settings_tab, text="Guardar Ajustes", command=self.save_settings, style="Cyber.TButton").pack(pady=20)

        self.load_settings()

    def create_about_tab(self, notebook):
        about_tab = ttk.Frame(notebook, style="Cyber.TFrame", padding=40)
        notebook.add(about_tab, text="💡 Acerca de")

        ttk.Label(about_tab, text="Impawnd-OSINT v5.0", font=("Consolas", 18, "bold"), foreground="#fff").pack(pady=10)
        ttk.Label(about_tab, text="Una herramienta de OSINT para entusiastas de la ciberseguridad.", style="Cyber.TLabel").pack(pady=5)

        # Enlace a Instagram
        instagram_link = ttk.Label(about_tab, text="Instagram del autor: @maxht_123", font=("Arial", 12, "underline"), foreground="#0af", cursor="hand2")
        instagram_link.pack(pady=20)
        instagram_link.bind("<Button-1>", lambda e: webbrowser.open("https://instagram.com/maxht_123"))

    def save_settings(self):
        config = {
            "numverify_api_key": self.numverify_api_key.get()
        }
        with open("config.json", "w") as f:
            json.dump(config, f)
        messagebox.showinfo("Éxito", "Ajustes guardados.")

    def load_settings(self):
        try:
            with open("config.json", "r") as f:
                config = json.load(f)
                self.numverify_api_key.set(config.get("numverify_api_key", ""))
        except FileNotFoundError:
            # No hay archivo de config, no pasa nada
            pass

if __name__ == "__main__":
    app = OSINTApp()
    if app.winfo_exists():
        app.mainloop()