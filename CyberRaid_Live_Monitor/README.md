# CyberRaid — Live Network Monitoring Prototype

Interactive Streamlit dashboard for authorized defensive network visibility.

## Included
- Dark interactive dashboard with metrics, timeline and protocol charts.
- Bounded laptop packet capture using Scapy.
- Basic packet metadata: IPs, protocol, ports, packet size and timestamp.
- Transparent port-based heuristic risk triage (not trained ML).
- Event filtering and CSV export.
- Home-network sensor guidance.

## Important limitations
- Does not automatically monitor all home Wi-Fi devices.
- Does not decrypt HTTPS or inspect message contents.
- Does not use the previously trained Random Forest model yet.
- Risk labels are simple heuristics and are not proof of an attack.
- Whole-home visibility needs supported router telemetry, port mirroring, or an authorized network sensor.

## Windows setup
Install Python 3.10/3.11. For packet capture, install Npcap: https://npcap.com/#download

In VS Code terminal (PowerShell):
```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```
Open the localhost URL printed in the terminal, usually http://localhost:8501.

If capture fails, run VS Code as Administrator, check Npcap installation and interface name. Machine-wide counters are available even without packet capture.

Only monitor networks/devices you own or are authorized to administer.
