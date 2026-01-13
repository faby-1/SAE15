import re
import csv
from collections import Counter


INPUT_FILE = 'tcpdump.txt'
OUTPUT_CSV = 'network_analysis.csv'
OUTPUT_HTML = 'dashboard_network.html'

def extract_data(filename):
    

    ip_pattern = re.compile(r'IP\s+([0-9a-zA-Z\-\.]+)\.\d+\s+>')
    ip_list = []
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            for line in file:
                match = ip_pattern.search(line)
                if match:
                    ip_list.append(match.group(1))
        return ip_list
    except FileNotFoundError:
        print(f"Erreur : Le fichier {filename} est introuvable.")
        return []

def generate_web_dashboard(top_5, all_counts):
    
   
    labels = [str(ip) for ip, count in top_5]
    values = [count for ip, count in top_5]

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Network Analysis - India Site</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f4f7f6; }}
            .container {{ max-width: 900px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; text-align: center; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
            th {{ background-color: #3498db; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .chart-container {{ position: relative; margin: auto; height: 40vh; width: 80vw; max-width: 800px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Network Traffic Dashboard</h1>
            <p><strong>Status:</strong> Analysis of tcpdump logs completed.</p>
            
            <div class="chart-container">
                <canvas id="myChart"></canvas>
            </div>

            <h2>Top 5 Suspect Addresses</h2>
            <table>
                <tr>
                    <th>Rank</th>
                    <th>Source Host / IP</th>
                    <th>Packet Count</th>
                </tr>
                {"".join([f"<tr><td>{i+1}</td><td>{ip}</td><td>{count}</td></tr>" for i, (ip, count) in enumerate(top_5)])}
            </table>
        </div>

        <script>
            const ctx = document.getElementById('myChart').getContext('2d');
            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: {labels},
                    datasets: [{{
                        label: 'Number of Packets',
                        data: {values},
                        backgroundColor: 'rgba(52, 152, 219, 0.7)',
                        borderColor: 'rgba(41, 128, 185, 1)',
                        borderWidth: 1
                    }}]
                }},
                options: {{ scales: {{ y: {{ beginAtZero: true }} }} }}
            }});
        </script>
    </body>
    </html>
    """
    with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f" Dashboard Web généré : {OUTPUT_HTML}")

def main():
    ips = extract_data(INPUT_FILE)
    if not ips: return
    
    counts = Counter(ips)
    top_5 = counts.most_common(5)
    
   
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Source', 'Count'])
        for ip, count in counts.items(): writer.writerow([ip, count])
    

    generate_web_dashboard(top_5, counts)
    print("\nTraitement terminé. Ouvrez 'dashboard_network.html' pour voir les résultats.")

if __name__ == "__main__":
    main()