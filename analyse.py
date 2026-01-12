import re
import csv
import tkinter as tk
from tkinter import filedialog, messagebox
from collections import Counter
import webbrowser
import os

def process_logs(input_file):
    # Regex robuste pour capturer l'heure, l'hôte source et l'hôte destination
    pattern = r"(\d{2}:\d{2}:\d{2}.\d+).+?IP\s+([\w\.-]+)\s+>\s+([\w\.-]+):"
    extracted_data = []
    sources = []

    try:
        with open(input_file, 'r', encoding='latin-1', errors='ignore') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    time, full_src, full_dst = match.groups()
                    src_parts = full_src.rsplit('.', 1)
                    dst_parts = full_dst.rsplit('.', 1)
                    src_host = src_parts[0]
                    src_port = src_parts[1] if len(src_parts) > 1 else "N/A"
                    dst_ip = dst_parts[0]
                    dst_port = dst_parts[1] if len(dst_parts) > 1 else "N/A"

                    extracted_data.append([time, src_host, src_port, dst_ip, dst_port])
                    sources.append(src_host)

        if not extracted_data:
            messagebox.showwarning("Error", "No data found.")
            return

        # --- 1. GÉNÉRATION DU CSV (Pour Excel) ---
        csv_path = 'traffic_analysis.csv'
        with open(csv_path, 'w', newline='', encoding='utf-8-sig') as csvfile:
            writer = csv.writer(csvfile, delimiter=';')
            writer.writerow(['Timestamp', 'Source_Host', 'Source_Port', 'Dest_IP', 'Dest_Port'])
            writer.writerows(extracted_data)

        # --- 2. GÉNÉRATION DE LA PAGE WEB (HTML) ---
        top_ips = Counter(sources).most_common(5)
        html_path = 'index.html'
        with open(html_path, 'w', encoding='utf-8') as h:
            h.write(f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Network Diagnostic Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f7f6; }}
                    h1 {{ color: #2c3e50; border-bottom: 2px solid #2c3e50; }}
                    .stats {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                    table {{ border-collapse: collapse; width: 100%; margin-top: 20px; background: white; }}
                    th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                    th {{ background-color: #34495e; color: white; }}
                    tr:nth-child(even) {{ background-color: #f2f2f2; }}
                    .alert {{ color: #e74c3c; font-weight: bold; }}
                </style>
            </head>
            <body>
                <h1> France-India Network Diagnostic Tool</h1>
                <div class="stats">
                    <p><strong>Total Packets Analyzed:</strong> {len(extracted_data)}</p>
                    <h2> Top 5 Suspicious Sources</h2>
                    <table>
                        <tr><th>Source Host</th><th>Packets Count</th></tr>
            """)
            for host, count in top_ips:
                h.write(f"<tr><td>{host}</td><td>{count}</td></tr>")
            
            h.write("""
                    </table>
                </div>
                <p style="margin-top:20px;"><i>Generated automatically for IT Services.</i></p>
            </body>
            </html>
            """)

        # Ouvrir automatiquement le site web à la fin du traitement
        webbrowser.open('file://' + os.path.realpath(html_path))
        messagebox.showinfo("Success", "Analysis complete! Opening the web report...")

    except Exception as e:
        messagebox.showerror("Error", str(e))

# --- INTERFACE TKINTER ---
def start_app():
    root = tk.Tk()
    root.title("France-India Diagnostic")
    root.geometry("400x200")
    tk.Label(root, text="Network Diagnostics Tool", font=("Arial", 14, "bold")).pack(pady=20)
    tk.Button(root, text="Select tcpdump file", command=lambda: select_file(root), 
              bg="#2c3e50", fg="white", font=("Arial", 10), padx=20, pady=10).pack()
    root.mainloop()

def select_file(window):
    path = filedialog.askopenfilename()
    if path: process_logs(path)

if __name__ == "__main__":
    start_app()