import subprocess
import time
import os
import csv
import requests
import argparse
from scapy.all import sniff, wrpcap, get_if_list
import threading


jar_dir = r"E:\Ataques DDOS\code\interfaz\sniffer\Cicflowmeter\CICFlowMeterV3-jnetpcap-1.4"
cic_jar_path = os.path.join(jar_dir, "CICFlowMeterV3.jar")
lib_dir = os.path.join(jar_dir, "lib", "/Cicflowmeter/CICFlowMeterV3-jnetpcap-1.4/*")
input_dir = os.path.join(jar_dir, "data", "/Cicflowmeter/CICFlowMeterV3-jnetpcap-1.4/data/in/")
output_dir = os.path.join(jar_dir, "data", "/Cicflowmeter/CICFlowMeterV3-jnetpcap-1.4/data/out/")
url = "http://localhost:8000/predecir/"
os.environ['PATH'] += os.pathsep + os.path.join(jar_dir, "lib")
pcap_file = os.path.join(input_dir, "captura.pcap")


def run_cicflowmeter():
    print("[*] Ejecutando CICFlowMeter...")
    cmd = [
        "java",
        "-cp",
        f"{cic_jar_path};{lib_dir}",
        "cic.cs.unb.ca.ifm.CICFlowMeter",
        input_dir,
        output_dir
    ]
    subprocess.run(cmd)
    print("[+] CICFlowMeter ha generado el archivo CSV.")


def count_flows(csv_file):
    with open(csv_file, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)  
        return sum(1 for _ in reader)


def send_csv(csv_file):
    print(f"[*] Enviando archivo {csv_file}...")
    with open(csv_file, 'rb') as f:
        response = requests.post(url, files={'file': f})
        if response.status_code == 200:
            print("[+] Archivo enviado correctamente.")
        else:
            print(f"[!] Error al enviar: {response.status_code}")


def run_scapy_sniffer(interface_name, flow_limit, capture_duration):
    captured_packets = []
    while True:  
        print(f"[*] Capturando tráfico en interfaz: {interface_name} por {capture_duration} segundos...")
        
       
        packets = sniff(iface=interface_name, timeout=capture_duration)
        captured_packets.extend(packets)
        
        
        wrpcap(pcap_file, captured_packets)

        
        threading.Thread(target=run_cicflowmeter).start()

       
        time.sleep(2)

        
        csv_file = None
        while not csv_file:
            time.sleep(1)
            for file in os.listdir(output_dir):
                if file.endswith(".csv"):
                    csv_file = os.path.join(output_dir, file)

        if csv_file:
            total_flows = count_flows(csv_file)
            print(f"[+] Flujos detectados: {total_flows}")

            
            if total_flows == 0:
                print("[!] El archivo CSV está vacío. No se enviará.")
                continue  

           
            if total_flows >= flow_limit:
                print(f"[+] Se ha alcanzado el número máximo de flujos: {total_flows}. Enviando archivo...")
                send_csv(csv_file)

            
            print(f"[+] Enviando archivo CSV...")  
            send_csv(csv_file)

       
        time.sleep(2)  

    print("[+] Fin de la captura y procesamiento.")  

def main():
    parser = argparse.ArgumentParser(description="Sniffer + CICFlowMeter + envío automático de CSV")
    parser.add_argument("interfaz", help="Nombre de la interfaz de red (ej: Wi-Fi, Ethernet, eth0)")
    parser.add_argument("limite", type=int, help="Número de flujos máximo para enviar CSV")
    parser.add_argument("--duracion", type=int, default=5, help="Duración de captura (segundos)")
    args = parser.parse_args()

    
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    
    run_scapy_sniffer(args.interfaz, args.limite, args.duracion)

if __name__ == "__main__":
    main()
