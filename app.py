from flask import Flask, render_template, jsonify, request
import socket
from scapy.all import conf, ARP, Ether, srp
import netifaces
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def get_protocol(port):
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return "unknown"

def is_connected():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 53))   # 구글 DNS에 실제 연결 시도
        s.close()
        return True
    except OSError:
        return False

def get_network_info():
    if not is_connected():
        return {"connected": False}
    try:
        gws = netifaces.gateways()
        gateway = gws['default'][netifaces.AF_INET][0]
        default_iface = gws['default'][netifaces.AF_INET][1]
        info = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
        return {"connected": True, "my_ip": info['addr'], "gateway": gateway}
    except Exception:
        return {"connected": False}

def ip_scan():
    gws = netifaces.gateways()
    default_iface = gws['default'][netifaces.AF_INET][1]
    default_address = netifaces.ifaddresses(default_iface)
    info = default_address[netifaces.AF_INET][0]
    my_ip = info['addr']
    subnet_mask = info['netmask']

    ip_addr = ipaddress.IPv4Network(f"{my_ip}/{subnet_mask}", strict=False)
    arp = ARP(pdst=str(ip_addr))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

def scan_ports(target, start_port, end_port):
    with ThreadPoolExecutor(max_workers=200) as executor:
        results = executor.map(
            lambda port: check_ports(target, port),
            range(start_port, end_port + 1)
        )
    open_ports = [p for p in results if p is not None]
    return open_ports
def check_ports(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((target, port))
    sock.close()
    if result == 0:
        return port
    return None

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/network")
def network():
    return jsonify(get_network_info())

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    start = int(data["start_port"])
    end = int(data["end_port"])

    devices = ip_scan()
    for device in devices:
        ports = scan_ports(device["ip"], start, end)
        device["ports"] = [
            {"port": p, "proto": get_protocol(p)} for p in ports
        ]
    return jsonify(devices)

if __name__ == '__main__':
    app.run(debug=True)