import os
import numpy as np
import pandas as pd
import torch
import joblib
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, classification_report
from pytorch_tabnet.tab_model import TabNetClassifier
from sklearn.preprocessing import LabelEncoder

dispositivo = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Usando dispositivo: {dispositivo}")

directorio = "E:\\Ataques DDOS\\datospreprocesados\\procesados2"
archivos = [
      "DrDoS_DNS.csv", "DrDoS_MSSQL.csv", "DrDoS_NetBIOS.csv",
        "DrDoS_NTP.csv", "DrDoS_SNMP.csv", "DrDoS_UDP.csv",
        "Syn.csv", "TFTP.csv"
]

df = pd.concat([ 
    pd.read_csv(os.path.join(directorio, archivo))
    for archivo in archivos
    if os.path.exists(os.path.join(directorio, archivo))
], ignore_index=True)

X = df.drop(columns=['Label']).values
y = df['Label'].values

print("Distribución de clases:\n", pd.Series(y).value_counts())

X = np.array(X, dtype=np.float32)
y = np.array(y, dtype=np.int64)

df_features = pd.DataFrame(X)

correlation_matrix = df_features.corr()

X = df_features.values

modelo = TabNetClassifier(
    n_d=32,                # dimensión del embedding para decisión
    n_a=32,                # dimensión para atención
    n_steps=5,             # pasos en la red TabNet
    gamma=1.5,             # controla la diversidad de máscaras de atención
    lambda_sparse=1e-4,    # penalización de dispersión (mayor = más disperso)
    cat_idxs=[],           # índices de columnas categóricas (vacío si todas son numéricas)
    cat_dims=[],           # número de clases por categórica
    cat_emb_dim=[],        # tamaño de embedding por categórica
    optimizer_fn=torch.optim.Adam,
    optimizer_params=dict(lr=1e-3),
    scheduler_fn=torch.optim.lr_scheduler.StepLR,
    scheduler_params=dict(step_size=10, gamma=0.9),
    mask_type="entmax",    
    device_name=dispositivo     
)

modelo.fit(
    X, y,
    max_epochs=35,
    patience=7,
    batch_size=1024,
    drop_last=False,
    virtual_batch_size=64,
    eval_metric=["logloss"]
)

y_pred = modelo.predict(X)
acc = accuracy_score(y, y_pred) * 100

report = classification_report(y, y_pred, output_dict=True)
f1_avg = report["weighted avg"]["f1-score"]

df_report = pd.DataFrame(report).transpose()

print(f"✅ Accuracy: {acc:.2f}%")
print(f"✅ F1-Score: {f1_avg:.2f}")

print("\n📊 Tabla de evaluación por clase:")
print(df_report)

ruta_reporte = "E:\\Ataques DDOS\\code\\saves\\classification_report.csv"
df_report.to_csv(ruta_reporte, index=True)
print(f"✅ Reporte guardado en: {ruta_reporte}")

ruta_modelo_tabnet = "E:\\Ataques DDOS\\code\\saves\\tabnet_model"
modelo.save_model(ruta_modelo_tabnet)
print(f"✅ Modelo final guardado en: {ruta_modelo_tabnet}")
