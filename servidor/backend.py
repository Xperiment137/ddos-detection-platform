from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse
import pandas as pd
import numpy as np
import shap
import traceback
from datetime import datetime
import locale
import torch
from pytorch_tabnet.tab_model import TabNetClassifier
from xgboost import XGBClassifier
from fastapi.middleware.cors import CORSMiddleware

USAR_TABNET = False  

TABNET_MODEL_PATH = "E:\\Ataques DDOS\\code\\saves\\tabnet_model.zip"
XGBOOST_MODEL_PATH = "E:\\Ataques DDOS\\saves\\xgboost_model.json"


try:
    locale.setlocale(locale.LC_TIME, 'es_ES.UTF-8')
except:
    try:
        locale.setlocale(locale.LC_TIME, 'Spanish_Spain.1252')
    except:
        pass



COLUMNAS_A_ELIMINAR = [
    'Flow ID', 'Source IP', 'Destination IP', 'Timestamp',
    'Total Length of Bwd Packets', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow IAT Std', 'Flow IAT Max',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'CWE Flag Count', 'ECE Flag Count', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Max','Fwd Packets/s','Idle Min'
]




ultimo_resumen = {}  
ultimo_conteo = {}

app = FastAPI()



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



try:
    if USAR_TABNET:
        modelo = TabNetClassifier()
        modelo.load_model(TABNET_MODEL_PATH)
        print("✅ Modelo TabNet cargado.")
    else:
        modelo = XGBClassifier()
        modelo.load_model(XGBOOST_MODEL_PATH)
        explainer = shap.TreeExplainer(modelo)
        print("✅ Modelo XGBoost cargado.")
except Exception as e:
    print("⚠️ Error cargando el modelo:", e)


clase_texto = {
    0: "DrDoS_DNS",
    1: "BENIGN",
    2: "DrDoS_MSSQL",
    3: "DrDoS_NetBIOS", 
    4: "DrDoS_NTP",
    5: "DrDoS_SNMP",
    6: "DrDoS_UDP",
    7: "Syn",
    8: "TFTP"
}

@app.post("/predecir/")
async def predecir(file: UploadFile = File(...)):
    global ultimo_resumen, ultimo_conteo
    ultimo_resumen = {}
    ultimo_conteo = {}
    try:
        
        df = pd.read_csv(file.file)

       
        df.columns = df.columns.str.strip()

       
        df = df.drop(columns=[col for col in COLUMNAS_A_ELIMINAR if col.strip() in df.columns], errors="ignore")
        print("Columnas restantes después de la eliminación:", df.columns)

       
        if "Label" in df.columns:
            label_original = df["Label"].values
            df = df.drop(columns=["Label"])
        else:
            label_original = None

        
        df = df.drop(columns=["Unnamed: 0"], errors="ignore")
        print(df.columns.tolist())
       
        df = df.fillna(0)

        
        X = df.values

        
        pred = modelo.predict(X)
        proba = modelo.predict_proba(X)

        
        print("📊 Probabilidades por línea:")
        for i, fila in enumerate(proba[:10]): 
            print(f"\n📌 Fila {i+1}:")
            print(f"  Predicción: {clase_texto.get(pred[i], 'Desconocido')}")
            print("  Probabilidades:")
            for j, prob in enumerate(fila):
                clase_nombre = clase_texto.get(j, f"Clase_{j}")
                print(f"    {clase_nombre}: {prob:.4f}")

       
        pred_texto = np.vectorize(lambda x: clase_texto.get(x, str(x)))(pred)

        
        confianzas = proba[np.arange(len(pred)), pred]
        confianza_media = float(np.mean(confianzas))  

       
        confianza_por_clase = {}
        for clase in clase_texto.values():
            indices_clase = [i for i, p in enumerate(pred_texto) if p == clase]
            if indices_clase:
                confianza_por_clase[clase] = float(np.mean([confianzas[i] for i in indices_clase]))  
            else:
                confianza_por_clase[clase] = 0.0

       
        df["Predicción"] = pred_texto
        if label_original is not None:
            df["Label original"] = label_original

      
        ultimo_conteo = pd.Series(pred_texto).value_counts().to_dict()

       
        clase_principal = pd.Series(pred_texto).mode()[0]
        if clase_principal == "BENIGN" and len(ultimo_conteo) > 1:
           
            clases_ordenadas = sorted(ultimo_conteo.items(), key=lambda x: x[1], reverse=True)
            segunda_clase = clases_ordenadas[1][0]
            valor_benign = ultimo_conteo.get("BENIGN", 0)
            valor_segundo = ultimo_conteo.get(segunda_clase, 0)

            
            umbral = 0.80  
            if valor_segundo >= valor_benign * umbral:
                clase_principal = segunda_clase

    
        resumen = {
            "fecha": datetime.now().strftime("%d %B %Y, %H:%M:%S"),
            "valor_mas_frecuente": clase_principal,
            "confianza_media": confianza_por_clase.get(clase_principal, 0.0),
            "conteo_por_clase": ultimo_conteo,
        }

        
        ultimo_resumen = {k: str(v) if isinstance(v, np.float32) else v for k, v in resumen.items()}

    except Exception as e:
        print("❌ Error al predecir:\n", traceback.format_exc())
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/resumen/")
async def resumen():
    if not ultimo_resumen:
        return JSONResponse(content={"mensaje": "No hay resumen generado aún."}, status_code=404)
    return ultimo_resumen

    
