"""
Generate flow and architecture diagrams matching the black background theme
for the CyberShield Cloud-Based Cyber Threat Detection presentation.
"""
import matplotlib.pyplot as plt
import matplotlib.patches as patches

def generate_process_flow_diagram():
    fig, ax = plt.subplots(figsize=(10, 7.5), dpi=150)
    fig.patch.set_facecolor('#000000')
    ax.set_facecolor('#000000')
    ax.set_xlim(0, 10.5)
    ax.set_ylim(0, 10.5)
    ax.axis('off')

    # Title
    ax.text(5, 9.5, "CLOUD-BASED CYBER THREAT DETECTION & MITIGATION PIPELINE", 
            color='white', fontsize=14, weight='bold', ha='center', va='center', fontfamily='sans-serif')

    # Box styling helper
    def draw_box(x, y, w, h, text, subtext="", edgecolor='#38bdf8', facecolor='#0f172a', textcolor='#ffffff'):
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.1,rounding_size=0.15",
                                     linewidth=1.8, edgecolor=edgecolor, facecolor=facecolor)
        ax.add_patch(rect)
        if subtext:
            ax.text(x + w/2, y + h/2 + 0.15, text, color=textcolor, fontsize=10, weight='bold', ha='center', va='center')
            ax.text(x + w/2, y + h/2 - 0.2, subtext, color='#94a3b8', fontsize=8, ha='center', va='center')
        else:
            ax.text(x + w/2, y + h/2, text, color=textcolor, fontsize=10, weight='bold', ha='center', va='center')

    def draw_arrow(x1, y1, x2, y2, color='#38bdf8', label=""):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="->", color=color, lw=1.8, mutation_scale=15))
        if label:
            ax.text((x1+x2)/2 + 0.15, (y1+y2)/2, label, color='#38bdf8', fontsize=9, weight='bold')

    # Row 1: Data Ingestion & Preprocessing
    draw_box(0.5, 7.8, 2.5, 1.0, "LOG DATA INGESTION", "CSV, JSON, Cloud Telemetry")
    draw_arrow(3.2, 8.3, 3.8, 8.3)
    draw_box(3.8, 7.8, 2.5, 1.0, "NORMALIZATION & PARSING", "11-Field Standard Schema")
    draw_arrow(6.5, 8.3, 7.1, 8.3)
    draw_box(7.1, 7.8, 2.5, 1.0, "FEATURE EXTRACTION", "Window Counts, Rates, Ports")

    # Downward arrow to Detection Engines
    draw_arrow(8.35, 7.7, 8.35, 6.7)
    draw_arrow(5.05, 7.7, 5.05, 6.7)

    # Row 2: Detection Dual Engine
    draw_box(1.0, 5.7, 3.8, 1.0, "RULE-BASED ENGINE", "Brute Force, Port Scan, Traffic Spike", edgecolor='#fbbf24')
    draw_box(5.5, 5.7, 3.8, 1.0, "ML ANOMALY ENGINE", "Isolation Forest (Unsupervised)", edgecolor='#a855f7')

    # Merge into Scoring & Correlation
    draw_arrow(2.9, 5.6, 4.3, 4.7)
    draw_arrow(7.4, 5.6, 5.7, 4.7)

    # Row 3: Risk Scoring & Alert Manager
    draw_box(3.5, 3.7, 3.0, 1.0, "RISK SCORING (0-100)", "LOW / MED / HIGH / CRIT", edgecolor='#f43f5e')

    # Decision Diamond
    draw_arrow(5.0, 3.6, 5.0, 2.8)
    
    # Diamond patch
    diamond = patches.Polygon([[5.0, 2.8], [6.2, 2.3], [5.0, 1.8], [3.8, 2.3]], 
                              closed=True, edgecolor='#38bdf8', facecolor='#1e293b', lw=1.8)
    ax.add_patch(diamond)
    ax.text(5.0, 2.3, "THREAT\nTRIGGERED?", color='#ffffff', fontsize=9, weight='bold', ha='center', va='center')

    # "NO" branch
    draw_arrow(3.8, 2.3, 1.8, 2.3, color='#22c55e', label="NO")
    draw_box(0.5, 1.8, 1.5, 1.0, "NORMAL LOG", "Archived", edgecolor='#22c55e', facecolor='#052e16')

    # "YES" branch
    draw_arrow(6.2, 2.3, 7.8, 2.3, color='#ef4444', label="YES")
    draw_box(7.8, 1.8, 1.8, 1.0, "ALERT DEDUP", "5-Min Window", edgecolor='#ef4444', facecolor='#450a0a')

    # Down from Alert Dedup to Output Actions
    draw_arrow(8.7, 1.7, 8.7, 0.9)
    draw_box(2.0, 0.2, 2.6, 0.7, "CLOUD DASHBOARD", "Overview & Analytics UI", edgecolor='#06b6d4')
    draw_box(4.9, 0.2, 2.6, 0.7, "INCIDENT WORKBENCH", "Forensic Investigation", edgecolor='#06b6d4')
    draw_box(7.8, 0.2, 2.0, 0.7, "REMEDIATION", "Block IP / Playbook", edgecolor='#ef4444')

    draw_arrow(8.0, 1.7, 3.3, 1.0)
    draw_arrow(8.4, 1.7, 6.2, 1.0)

    plt.tight_layout()
    output_path = '/Users/ak/Documents/Cp-01/cloud-cyber-threat-detection-dashboard/screenshots/pipeline_flow_diagram.png'
    plt.savefig(output_path, facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()
    print("Process Flow diagram generated at:", output_path)

if __name__ == '__main__':
    generate_process_flow_diagram()
