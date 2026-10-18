import time
from datetime import datetime
import pandas as pd
import streamlit as st
import plotly.express as px
import psutil

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

st.set_page_config(page_title="CyberRaid | Live Monitor", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp{background:radial-gradient(ellipse at top right,#14223a 0%,#0a1020 44%,#080d18 100%);color:#e8eef9}
section[data-testid="stSidebar"]{background:#0c1424;border-right:1px solid #263650}
.block-container{padding-top:1.6rem;max-width:1500px}
div[data-testid="stMetric"]{background:#111d31;border:1px solid #263650;padding:16px;border-radius:14px}
</style>""", unsafe_allow_html=True)

if "events" not in st.session_state: st.session_state.events = []
if "last_net" not in st.session_state:
    n=psutil.net_io_counters(); st.session_state.last_net=(time.time(),n.bytes_sent,n.bytes_recv)

def assess(proto, length, dport):
    # Transparent demo heuristic, NOT a trained ML prediction.
    if proto=="TCP" and dport in {4444,1337,31337}:
        return "High", f"Unusual destination port {dport}; verify context"
    if proto=="TCP" and dport in {22,23,3389,445,1433,3306}:
        return "Medium", f"Connection to commonly sensitive port {dport}"
    return "Low", "No configured port heuristic triggered"

def add_event(src,dst,proto,length,sport=None,dport=None,source="Laptop capture"):
    risk,note=assess(proto,int(length),dport)
    st.session_state.events.append({"time":datetime.now().strftime("%H:%M:%S"),"source":source,"src":str(src),"dst":str(dst),"proto":proto,"bytes":int(length),"src_port":sport,"dst_port":dport,"risk":risk,"note":note})
    st.session_state.events=st.session_state.events[-1000:]

def packet_callback(pkt):
    if IP not in pkt: return
    proto="OTHER"; sport=dport=None
    if TCP in pkt: proto="TCP"; sport=int(pkt[TCP].sport); dport=int(pkt[TCP].dport)
    elif UDP in pkt: proto="UDP"; sport=int(pkt[UDP].sport); dport=int(pkt[UDP].dport)
    elif ICMP in pkt: proto="ICMP"
    add_event(pkt[IP].src,pkt[IP].dst,proto,len(pkt),sport,dport)

st.sidebar.markdown("## 🛡️ CyberRaid")
st.sidebar.caption("Defensive network visibility")
page=st.sidebar.radio("NAVIGATION",["Overview","Laptop Capture","Home Network Sensor","Events & Export","Setup Guide"])
st.sidebar.divider()
st.sidebar.caption("Only monitor networks/devices you own or are authorized to administer.")
st.title("🛡️ CyberRaid")
st.caption("Local network security console · Student monitoring prototype")

df=pd.DataFrame(st.session_state.events)
total=len(df)
high=int((df.risk=="High").sum()) if total else 0
medium=int((df.risk=="Medium").sum()) if total else 0
ips=len(set(df.src.tolist()+df.dst.tolist())) if total else 0

if page=="Overview":
    a,b,c,d=st.columns(4); a.metric("Captured events",f"{total:,}"); b.metric("High-risk heuristics",f"{high:,}"); c.metric("Medium-risk heuristics",f"{medium:,}"); d.metric("Distinct IPs",f"{ips:,}")
    l,r=st.columns([1.2,1])
    with l:
        st.subheader("Traffic timeline")
        if total:
            tl=df.groupby("time",as_index=False).size().rename(columns={"size":"Events"})
            st.plotly_chart(px.area(tl,x="time",y="Events",title="Observed packets/events"),use_container_width=True)
        else: st.info("No captured events yet. Open Laptop Capture or load demo events.")
    with r:
        st.subheader("Protocol distribution")
        if total:
            protos=df.proto.value_counts().rename_axis("Protocol").reset_index(name="Count")
            st.plotly_chart(px.pie(protos,names="Protocol",values="Count",hole=.62),use_container_width=True)
        else: st.info("Protocol chart appears after capture.")
    st.subheader("Recent events")
    if total: st.dataframe(df.tail(12).iloc[::-1],use_container_width=True,hide_index=True)
    else: st.caption("No event records yet.")
    st.warning("Risk labels use transparent port heuristics, not the trained Random Forest. A flagged port is not proof of an attack.")

elif page=="Laptop Capture":
    st.subheader("Laptop traffic capture")
    st.write("Capture packet metadata from this computer's network interface.")
    st.info("On Windows, install Npcap and run VS Code/PowerShell as Administrator if required. HTTPS contents are not decrypted.")
    if not SCAPY_OK: st.error("Scapy unavailable. Install requirements, then install Npcap on Windows.")
    iface=st.text_input("Network interface (optional)",value="",help="Leave blank for Scapy's default interface.")
    c1,c2=st.columns(2)
    count=c1.number_input("Packets to capture",min_value=10,max_value=5000,value=200,step=10)
    timeout=c2.number_input("Capture timeout (seconds)",min_value=5,max_value=120,value=20,step=5)
    if st.button("▶ Start bounded capture",type="primary",disabled=not SCAPY_OK):
        try:
            with st.spinner(f"Capturing up to {int(count)} packets for {int(timeout)} seconds…"):
                kwargs={"count":int(count),"timeout":int(timeout),"store":True,"prn":packet_callback}
                if iface.strip(): kwargs["iface"]=iface.strip()
                sniff(**kwargs)
            st.success(f"Capture finished. Stored events: {len(st.session_state.events)}")
            st.rerun()
        except Exception as e:
            st.error(f"Capture failed: {e}")
            st.caption("Check Npcap, interface name, and administrator permissions.")
    st.subheader("Machine-wide interface counters")
    now=time.time(); net=psutil.net_io_counters(); old_t,old_s,old_r=st.session_state.last_net
    x,y=st.columns(2); x.metric("Bytes sent since previous check",f"{max(net.bytes_sent-old_s,0):,}"); y.metric("Bytes received since previous check",f"{max(net.bytes_recv-old_r,0):,}")
    st.session_state.last_net=(now,net.bytes_sent,net.bytes_recv)
    st.caption("Counters are machine-wide between page checks, not per-device attribution.")

elif page=="Home Network Sensor":
    st.subheader("Whole-home Wi-Fi visibility")
    st.write("A normal Wi-Fi laptop usually sees its own unicast traffic, not every other device's traffic.")
    st.markdown("""
**Ways to obtain authorized home-network telemetry**
1. Router API/statistics, if your router supports it.
2. Managed switch/router port mirroring to a sensor computer.
3. A dedicated gateway/sensor.
4. Per-device agents on devices you administer.

This prototype does not bypass Wi-Fi isolation or secretly inspect devices. Encrypted traffic content is not decoded.
""")
    st.markdown("### Add a sample sensor event (UI testing)")
    with st.form("sensor_event"):
        x,y,z=st.columns(3); src=x.text_input("Source IP","192.168.1.10"); dst=y.text_input("Destination IP","1.1.1.1"); proto=z.selectbox("Protocol",["TCP","UDP","ICMP","OTHER"])
        p,q,r=st.columns(3); size=p.number_input("Packet size (bytes)",1,65535,512); sport=q.number_input("Source port",0,65535,51500); dport=r.number_input("Destination port",0,65535,443)
        submit=st.form_submit_button("Add sample metadata event")
    if submit:
        add_event(src,dst,proto,size,int(sport) or None,int(dport) or None,"Manual sensor demo")
        st.success("Sample event added. This is not a live router integration.")
        st.rerun()
    st.caption("Real whole-home monitoring requires router/sensor integration; feasibility depends on the router model.")

elif page=="Events & Export":
    st.subheader("Event explorer")
    if total:
        x,y=st.columns(2); risks=x.multiselect("Risk",["Low","Medium","High"],default=["Low","Medium","High"]); protos=y.multiselect("Protocol",sorted(df.proto.unique()),default=sorted(df.proto.unique()))
        filtered=df[df.risk.isin(risks)&df.proto.isin(protos)]
        st.dataframe(filtered.iloc[::-1],use_container_width=True,hide_index=True)
        st.download_button("⬇ Download filtered events CSV",filtered.to_csv(index=False).encode("utf-8"),"cyberraid_events.csv","text/csv")
        if st.button("Clear local event history"): st.session_state.events=[]; st.rerun()
    else: st.info("No events yet. Capture packets or add a sample event.")
    st.caption("Events live in this app session; no database persistence is configured.")

else:
    st.subheader("Run in VS Code")
    st.code(r"""py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py""",language="powershell")
    st.markdown("[Official Npcap download](https://npcap.com/#download)")
    st.markdown("""
**Limits**
- This is a local defensive prototype, not a production IDS.
- Current risk triage is heuristic, not a trained ML model.
- It does not decrypt HTTPS or inspect message contents.
- Whole-home monitoring requires router telemetry, traffic mirroring, or a sensor.
- Use only on networks you own or are authorized to monitor.
""")
