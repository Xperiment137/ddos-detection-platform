import pandas as pd
from sklearn.preprocessing import LabelEncoder
import numpy as np
import os

ruta_directorio = "E:\\Ataques DDOS"
ruta_guardado = "E:\\Ataques DDOS\\datospreprocesados"

archivos = [
    "DrDoS_DNS.csv", "DrDoS_LDAP.csv", "DrDoS_MSSQL.csv", "DrDoS_NetBIOS.csv",
    "DrDoS_NTP.csv", "DrDoS_SNMP.csv", "DrDoS_SSDP.csv", "DrDoS_UDP.csv",
    "Syn.csv", "TFTP.csv", "UDPLag.csv"
]

if not os.path.exists(ruta_guardado):
    os.makedirs(ruta_guardado)

le = LabelEncoder()

valores_labels = {}

columnas_a_eliminar_fijas = [
    "Unnamed: 0","Timestamp", "Flow ID", "Source IP", "Destination IP", "SimillarHTTP",
    "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "FIN Flag Count",
    "PSH Flag Count", "ECE Flag Count", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", 
    "Bwd Avg Bulk Rate",'CWE Flag Count', 'min_seg_size_forward', 'Inbound'
]

for archivo in archivos:
    ruta_archivo = os.path.join(ruta_directorio, archivo)

    df = pd.read_csv(ruta_archivo)

    df.columns = df.columns.str.strip()

    for label in df['Label'][1:]:  
        if label not in valores_labels:
            valores_labels[label] = len(valores_labels) 

    df['Label'] = df['Label'].map(valores_labels) 

    df['Label'] = df['Label'].astype(int)

    df.drop(columns=columnas_a_eliminar_fijas, errors="ignore", inplace=True)

    df.replace([np.inf, -np.inf], np.nan, inplace=True) 
    df.fillna(0, inplace=True)  

    ruta_guardado_archivo = os.path.join(ruta_guardado, archivo)
    df.to_csv(ruta_guardado_archivo, index=False)
    
    print(f"Archivo procesado y guardado en: {ruta_guardado_archivo}")

print("\nRelación final de 'Label' (Original -> Codificado):")
for original, codificado in valores_labels.items():
    print(f"{original} -> {codificado}")
