import os
import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import shap
import matplotlib.pyplot as plt
from pytorch_tabnet.tab_model import TabNetClassifier

# 📌 Parámetros
fila_inicio = 1
num_filas = 1000
USAR_TABNET = False

# 📂 Rutas
ruta_directorio = "E:\\Ataques DDOS\\datospreprocesados\\procesados3"
ruta_salida = "E:\\Ataques DDOS\\datospreprocesados\\predicciones"
TABNET_MODEL_PATH = "E:\\Ataques DDOS\\code\\saves\\tabnet_model.zip"
XGBOOST_MODEL_PATH = "E:\\Ataques DDOS\\saves\\xgboost_model.json"

# 📄 Archivos a procesar
archivos = [
    "output_flows.csv"
]

# Crear carpeta de salida si no existe
os.makedirs(ruta_salida, exist_ok=True)

# 🔄 Inicializar matriz global
matriz_predicciones_global = pd.DataFrame()

# Cargar modelo
try:
    if USAR_TABNET:
        modelo = TabNetClassifier()
        modelo.load_model(TABNET_MODEL_PATH)
        print("✅ Modelo TabNet cargado.")
    else:
        modelo = XGBClassifier()
        modelo.load_model(XGBOOST_MODEL_PATH)
        print("✅ Modelo XGBoost cargado.")
except Exception as e:
    print("⚠️ Error cargando el modelo:", e)
    modelo = None

def plot_shap_force(explainer, shap_values, X_instance):
    shap.initjs()
    if isinstance(shap_values, list):
        shap_val = shap_values[0][0]
        expected_val = explainer.expected_value[0]
    elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
        shap_val = shap_values[0, :, 0]
        expected_val = explainer.expected_value[0]
    else:
        shap_val = shap_values[0]
        expected_val = explainer.expected_value

    return shap.plots.force(expected_val, shap_val, X_instance)

# 🔁 Procesar cada archivo
for archivo in archivos:
    ruta_csv = os.path.join(ruta_directorio, archivo)

    if not os.path.exists(ruta_csv):
        print(f"🚫 Archivo no encontrado: {ruta_csv}")
        continue

    print(f"\n📂 Procesando archivo: {archivo}")

    df_completo = pd.read_csv(ruta_csv)
    print(f"🔍 Número de columnas en el DataFrame original: {df_completo.shape[1]}")

    df_temp = df_completo.iloc[fila_inicio:fila_inicio + num_filas].copy()
    print(f"🔍 Número de columnas después de seleccionar las filas: {df_temp.shape[1]}")

    columnas_a_eliminar = ['Fwd IAT Max', 'Idle Max', 'RST Flag Count', 'Packet Length Mean', 'Flow IAT Std', 
        'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Idle Min', 'Subflow Bwd Packets', 'Fwd IAT Total',
        'Average Packet Size', 'Bwd IAT Max', 'Avg Fwd Segment Size', 'Packet Length Std', 'Packet Length Variance',
        'Subflow Bwd Bytes', 'Active Max', 'Avg Bwd Segment Size', 'act_data_pkt_fwd', 'Fwd IAT Min', 'Active Min',
        'Flow IAT Max', 'Fwd IAT Std', 'Subflow Fwd Bytes', 'Bwd IAT Std', 'Fwd Header Length.1', 'ACK Flag Count',
        'Idle Mean', 'Total Length of Bwd Packets', 'Subflow Fwd Packets', 'Max Packet Length', 'Fwd Packets/s',
        'Bwd Packet Length Std', 'Min Packet Length', 'Fwd IAT Mean'
    ]

    df_temp = df_temp.drop(columns=[col for col in columnas_a_eliminar if col in df_temp.columns])

    if "Unnamed: 0" in df_temp.columns:
        df_temp = df_temp.drop(columns=["Unnamed: 0"])
        print("🛑 Se eliminó la columna 'Unnamed: 0'.")

    print(f"🔍 Número de columnas después de eliminar las columnas específicas: {df_temp.shape[1]}")
    print("🧽 Columnas específicas eliminadas antes de la predicción.")

    # Guardar y quitar columna 'Label'
    label_original = None
    if "Label" in df_temp.columns:
        label_original = df_temp["Label"].values
        df_temp = df_temp.drop(columns=["Label"])
        print("✅ Se guardó la columna 'Label' antes de eliminarla.")

    df_temp = df_temp.fillna(0)
    X_nuevo = df_temp.values

    # 🔮 Predicción
    predicciones = modelo.predict(X_nuevo)

    # 🎯 Accuracy
    if label_original is not None:
        accuracy = accuracy_score(label_original, predicciones)
        print(f"🎯 Accuracy en {archivo}: {accuracy:.4f}")
    else:
        accuracy = None
        print("⚠️ No se encontró la columna 'Label', no se puede calcular la accuracy.")

    # ➕ Agregar columnas de predicción y archivo
    df_temp["Predicción"] = predicciones
    if label_original is not None:
        df_temp["Label original"] = label_original
    df_temp["Archivo"] = archivo

    # 🖨️ Mostrar predicciones por consola
    print("\n📌 Predicciones:")
    print(df_temp[["Predicción"]])

    # 💾 Guardar predicciones individuales
    ruta_salida_archivo = os.path.join(ruta_salida, f"predicciones_{archivo}")
    df_temp.to_csv(ruta_salida_archivo, index=False)
    print(f"✅ Predicciones guardadas en: {ruta_salida_archivo}")

    # 🧩 Acumular en matriz global
    matriz_predicciones_global = pd.concat([matriz_predicciones_global, df_temp], ignore_index=True)

    # 📊 SHAP (solo para XGBoost)
    if not USAR_TABNET:
        try:
            explainer = shap.Explainer(modelo)
            shap_values = explainer.shap_values(X_nuevo)
            shap.summary_plot(shap_values, X_nuevo, feature_names=df_temp.columns, max_display=20)
            plot_shap_force(explainer, shap_values, X_nuevo[0])
            print("✅ SHAP explainer inicializado para XGBoost.")
        except Exception as e:
            print("❌ No se pudo inicializar SHAP para este modelo:", e)

# 💾 Guardar matriz global
ruta_matriz_global = os.path.join(ruta_salida, "matriz_predicciones_global.csv")
matriz_predicciones_global.to_csv(ruta_matriz_global, index=False)
print(f"\n📊 Matriz global de predicciones guardada en: {ruta_matriz_global}")
print("\n✅ Proceso completado para todos los archivos.")
