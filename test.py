import re
import csv
from collections import Counter

INPUT_FILE = 'tcpdump.txt'
OUTPUT_CSV_IPS = 'analyse_reseau.csv'
OUTPUT_CSV_PROTOCOLS = 'analyse_protocle.csv'
OUTPUT_HTML = 'website.html'

def extract_data(filename):
    """Extrait les adresses IP et les protocoles du fichier tcpdump"""
    
   
    ip_pattern = re.compile(r'IP\s+([0-9a-zA-Z\-\.]+)\.\d+\s+>')
    
   
    protocol_pattern = re.compile(r':\s+([A-Z]+)')
    
    # Pattern alternatif pour les protocoles en début de ligne
    protocol_pattern2 = re.compile(r'^([A-Z]+[0-9]*)\s+')
    
    ip_list = []
    protocol_list = []
    
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            for line in file:
                # Extraction des IPs
                ip_match = ip_pattern.search(line)
                if ip_match:
                    ip_list.append(ip_match.group(1))
                
                # Extraction des protocoles (méthode 1)
                protocol_match = protocol_pattern.search(line)
                if protocol_match:
                    protocol_list.append(protocol_match.group(1))
                else:
                    # Extraction des protocoles (méthode 2 - début de ligne)
                    protocol_match2 = protocol_pattern2.search(line.strip())
                    if protocol_match2:
                        proto = protocol_match2.group(1)
                        # Filtrer les protocoles valides
                        if proto in ['TCP', 'UDP', 'ICMP', 'ARP', 'IP', 'IP6', 'DNS', 'HTTP', 'HTTPS', 'FTP', 'SSH']:
                            protocol_list.append(proto)
                
        return ip_list, protocol_list
        
    except FileNotFoundError:
        print(f"Erreur : Le fichier {filename} est introuvable.")
        return [], []

def save_to_csv(data_dict, filename, headers):
    """Sauvegarde les données dans un fichier CSV"""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for item, count in data_dict.items():
            writer.writerow([item, count])

def generate_web_dashboard(top_5_ips, all_ip_counts, protocol_counts):
    """Génère le dashboard web complet avec IPs et protocoles"""
    
    # Données pour le graphique des IPs
    ip_labels = [str(ip) for ip, count in top_5_ips]
    ip_values = [count for ip, count in top_5_ips]
    
    # Données pour le graphique des protocoles
    protocol_labels = [str(proto) for proto, count in protocol_counts.most_common(10)]
    protocol_values = [count for proto, count in protocol_counts.most_common(10)]
    
    # Statistiques générales
    total_ips = len(all_ip_counts)
    total_packets = sum(all_ip_counts.values())
    total_protocols = len(protocol_counts)
    

    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Analyse Réseau Complète - Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                margin: 20px; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }}
            .container {{ 
                max-width: 1200px; 
                margin: auto; 
                background: white; 
                padding: 30px; 
                border-radius: 15px; 
                box-shadow: 0 10px 30px rgba(0,0,0,0.3); 
            }}
            h1 {{ 
                color: #2c3e50; 
                text-align: center; 
                margin-bottom: 30px;
                font-size: 2.5em;
            }}
            h2 {{ 
                color: #34495e; 
                border-bottom: 3px solid #3498db; 
                padding-bottom: 10px; 
            }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }}
            .stat-card {{
                background: linear-gradient(135deg, #3498db, #2980b9);
                color: white;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }}
            .stat-number {{
                font-size: 2em;
                font-weight: bold;
                margin-bottom: 5px;
            }}
            .charts-container {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 30px;
                margin: 30px 0;
            }}
            .chart-wrapper {{
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 3px 10px rgba(0,0,0,0.1);
            }}
            .chart-container {{ 
                position: relative; 
                height: 400px; 
                width: 100%; 
            }}
            table {{ 
                width: 100%; 
                border-collapse: collapse; 
                margin-top: 20px; 
                box-shadow: 0 3px 10px rgba(0,0,0,0.1);
            }}
            th, td {{ 
                padding: 15px; 
                border: 1px solid #ddd; 
                text-align: left; 
            }}
            th {{ 
                background: linear-gradient(135deg, #e74c3c, #c0392b); 
                color: white; 
                font-weight: bold;
            }}
            tr:nth-child(even) {{ 
                background-color: #f2f2f2; 
            }}
            tr:hover {{
                background-color: #e8f4f8;
            }}
            .danger {{ color: #e74c3c; font-weight: bold; }}
            .warning {{ color: #f39c12; font-weight: bold; }}
            .safe {{ color: #27ae60; font-weight: bold; }}
            @media (max-width: 768px) {{
                .charts-container {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Dashboard Analyse Réseau Complète</h1>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{total_packets:,}</div>
                    <div>Paquets Totaux</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_ips}</div>
                    <div>Adresses IP Uniques</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{total_protocols}</div>
                    <div>Protocoles Détectés</div>
                </div>
            </div>

            <div class="charts-container">
                <div class="chart-wrapper">
                    <h3>Top 5 Adresses IP Suspectes</h3>
                    <div class="chart-container">
                        <canvas id="ipChart"></canvas>
                    </div>
                </div>
                
                <div class="chart-wrapper">
                    <h3>Distribution des Protocoles</h3>
                    <div class="chart-container">
                        <canvas id="protocolChart"></canvas>
                    </div>
                </div>
            </div>

            <h2>🚨 Top 10 Adresses IP Menaçantes</h2>
            <table>
                <tr>
                    <th>Rang</th>
                    <th>Adresse IP / Host</th>
                    <th>Nombre de Paquets</th>
                    <th>Niveau de Menace</th>
                </tr>
                {"".join([
                    f'<tr><td>{i+1}</td><td>{ip}</td><td>{count:,}</td><td class="{"danger" if count > 1000 else "warning" if count > 500 else "safe"}">'
                    f'{"🔴 Critique" if count > 1000 else "🟡 Élevé" if count > 500 else "🟢 Modéré"}</td></tr>'
                    for i, (ip, count) in enumerate(all_ip_counts.most_common(10))
                ])}
            </table>

            <h2>📊 Protocoles Réseau Détectés</h2>
            <table>
                <tr>
                    <th>Rang</th>
                    <th>Protocole</th>
                    <th>Nombre d'Occurrences</th>
                    <th>Pourcentage</th>
                </tr>
                {"".join([
                    f'<tr><td>{i+1}</td><td>{proto}</td><td>{count:,}</td><td>{(count/sum(protocol_counts.values())*100):.1f}%</td></tr>'
                    for i, (proto, count) in enumerate(protocol_counts.most_common())
                ])}
            </table>
        </div>

        <script>
            // Graphique des IPs
            const ipCtx = document.getElementById('ipChart').getContext('2d');
            new Chart(ipCtx, {{
                type: 'bar',
                data: {{
                    labels: {ip_labels},
                    datasets: [{{
                        label: 'Nombre de Paquets',
                        data: {ip_values},
                        backgroundColor: [
                            'rgba(231, 76, 60, 0.8)',
                            'rgba(243, 156, 18, 0.8)',
                            'rgba(52, 152, 219, 0.8)',
                            'rgba(155, 89, 182, 0.8)',
                            'rgba(39, 174, 96, 0.8)'
                        ],
                        borderColor: [
                            'rgba(231, 76, 60, 1)',
                            'rgba(243, 156, 18, 1)',
                            'rgba(52, 152, 219, 1)',
                            'rgba(155, 89, 182, 1)',
                            'rgba(39, 174, 96, 1)'
                        ],
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            grid: {{
                                color: 'rgba(0,0,0,0.1)'
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            display: true,
                            position: 'top'
                        }}
                    }}
                }}
            }});

            // Graphique des protocoles
            const protocolCtx = document.getElementById('protocolChart').getContext('2d');
            new Chart(protocolCtx, {{
                type: 'doughnut',
                data: {{
                    labels: {protocol_labels},
                    datasets: [{{
                        label: 'Protocoles',
                        data: {protocol_values},
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.8)',
                            'rgba(54, 162, 235, 0.8)',
                            'rgba(255, 205, 86, 0.8)',
                            'rgba(75, 192, 192, 0.8)',
                            'rgba(153, 102, 255, 0.8)',
                            'rgba(255, 159, 64, 0.8)',
                            'rgba(199, 199, 199, 0.8)',
                            'rgba(83, 102, 255, 0.8)',
                            'rgba(255, 99, 255, 0.8)',
                            'rgba(99, 255, 132, 0.8)'
                        ],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'right'
                        }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """
    
    with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"📊 Dashboard Web complet généré : {OUTPUT_HTML}")

def main():
    print("🔍 Début de l'analyse des logs réseau...")
    
    # Extraction des données
    ips, protocols = extract_data(INPUT_FILE)
    
    if not ips and not protocols:
        print("❌ Aucune donnée extraite. Vérifiez le fichier d'entrée.")
        return
    
    # Comptage des occurrences
    ip_counts = Counter(ips)
    protocol_counts = Counter(protocols)
    top_5_ips = ip_counts.most_common(5)
    
    # Sauvegarde en CSV
    save_to_csv(ip_counts, OUTPUT_CSV_IPS, ['Adresse_IP', 'Nombre_Paquets'])
    save_to_csv(protocol_counts, OUTPUT_CSV_PROTOCOLS, ['Protocole', 'Nombre_Occurrences'])
    
    # Génération du dashboard
    generate_web_dashboard(top_5_ips, ip_counts, protocol_counts)
    
    # Affichage des résultats
    print(f"\n📈 Statistiques générales :")
    print(f"   • {len(ip_counts)} adresses IP uniques détectées")
    print(f"   • {sum(ip_counts.values()):,} paquets au total")
    print(f"   • {len(protocol_counts)} protocoles différents")
    
    print(f"\n🚨 Top 5 adresses IP les plus actives :")
    for i, (ip, count) in enumerate(top_5_ips, 1):
        print(f"   {i}. {ip}: {count:,} paquets")
    
    print(f"\n Protocoles détectés :")
    for proto, count in protocol_counts.most_common():
        percentage = (count / sum(protocol_counts.values())) * 100
        print(f"   • {proto}: {count:,} ({percentage:.1f}%)")
    
    print(f"\n Fichiers générés :")
    print(f"   • {OUTPUT_CSV_IPS} (données IP)")
    print(f"   • {OUTPUT_CSV_PROTOCOLS} (données protocoles)")
    print(f"   • {OUTPUT_HTML} (dashboard web)")
    
    print(f"\n🌐 Ouvrez '{OUTPUT_HTML}' dans votre navigateur pour voir le dashboard complet.")

if __name__ == "__main__":
    main()
