from scapy.all import sniff
import subprocess

# Konfigurasi
IP_AMAN = "165.232.182.177"  # IP yang ingin diamankan
PORT_AMAN = 9999           # Port yang ingin diamankan
THRESHOLD = 100          # Jumlah paket per detik yang dianggap sebagai serangan

# Dictionary untuk menyimpan hitungan paket per IP
ip_counter = {}

def block_ip(ip):
    # Memblokir IP dengan menggunakan iptables
    command = f"sudo iptables -A INPUT -s {ip} -j DROP"
    subprocess.run(command, shell=True)
    print(f"[INFO] IP {ip} telah diblokir.")

def packet_callback(packet):
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        dport = packet["TCP"].dport if packet.haslayer("TCP") else None
        
        if ip_dst == IP_AMAN and dport == PORT_AMAN:
            # Hitung paket dari IP sumber
            if ip_src not in ip_counter:
                ip_counter[ip_src] = 1
            else:
                ip_counter[ip_src] += 1
            
            # Jika melebihi threshold, blokir IP
            if ip_counter[ip_src] > THRESHOLD:
                block_ip(ip_src)

def reset_counter():
    global ip_counter
    ip_counter = {}
    print("[INFO] Counter reset.")

if __name__ == "__main__":
    print(f"[INFO] Monitoring traffic to {IP_AMAN}:{PORT_AMAN}")
    # Menggunakan sniff untuk memonitor trafik ke IP dan port yang diamankan
    sniff(filter=f"host {IP_AMAN} and port {PORT_AMAN}", prn=packet_callback, store=0)
