import pandas as pd
import os
import numpy as np
import time
import matplotlib.pyplot as plt
import seaborn as sns

ruta_directorio = "E:\\Ataques DDOS\\datospreprocesados"
ruta_guardado = "E:\\Ataques DDOS\\datospreprocesados\\procesados2"
ruta_descartados = "E:\\Ataques DDOS\\datospreprocesados\\procesados3"

os.makedirs(ruta_guardado, exist_ok=True)
os.makedirs(ruta_descartados, exist_ok=True)

archivos = [
    "DrDoS_DNS.csv", "DrDoS_MSSQL.csv", "DrDoS_NetBIOS.csv",
    "DrDoS_NTP.csv", "DrDoS_SNMP.csv", "DrDoS_UDP.csv",
    "Syn.csv", "TFTP.csv", "UDPLag.csv", "DrDoS_LDAP.csv", "DrDoS_SSDP.csv"
]

archivos_excluir = ["DrDoS_LDAP.csv", "DrDoS_SSDP.csv", "UDPLag.csv"]

CLASE_ELIMINAR = 12
CLASE_BASE = 1
ENTRADAS_OBJETIVO = 56863
ENTRADAS_DESCARTADAS = 1000

archivos_existentes = [f for f in archivos if os.path.exists(os.path.join(ruta_guardado, f))]



if not archivos_existentes:
    print("\n🧹 Paso 1: Procesando y balanceando archivos...\n")

    for archivo in archivos:
        start_time = time.time()
        print(f"📂 Procesando archivo: {archivo}")
        ruta_archivo = os.path.join(ruta_directorio, archivo)
        df = pd.read_csv(ruta_archivo)
        df.columns = df.columns.str.strip()
        df = df[df["Label"] != CLASE_ELIMINAR]

        conteo_etiquetas = df["Label"].value_counts()
        print(f"📊 Conteo de etiquetas:\n{conteo_etiquetas.to_string()}")

        df_balanceado = pd.DataFrame()
        df_descartados_total = pd.DataFrame()

        for label, count in conteo_etiquetas.items():
            df_clase = df[df["Label"] == label]
            if label == CLASE_BASE or count <= ENTRADAS_OBJETIVO:
                df_balanceado = pd.concat([df_balanceado, df_clase])
            else:
                df_mantener = df_clase.sample(ENTRADAS_OBJETIVO, random_state=42)
                df_descartar = df_clase.drop(df_mantener.index)
                df_balanceado = pd.concat([df_balanceado, df_mantener])
                df_descartados_total = pd.concat([
                    df_descartados_total,
                    df_descartar.sample(min(len(df_descartar), ENTRADAS_DESCARTADAS), random_state=42)
                ])
            print(f"⚖️ Clase {label}: {min(count, ENTRADAS_OBJETIVO)} entradas mantenidas")

        df_balanceado.to_csv(os.path.join(ruta_guardado, archivo), index=False)
        print(f"✅ Balanceado guardado en: {ruta_guardado}")

        if not df_descartados_total.empty:
            df_descartados_total.to_csv(os.path.join(ruta_descartados, archivo), index=False)
            print(f"🔹 Descartados guardados en: {ruta_descartados}")

        print(f"⏱️ Tiempo: {round(time.time() - start_time, 2)} segundos\n")



print("\n🗑️ Paso 2: Eliminando archivos no deseados...\n")
for archivo in archivos_excluir:
    for carpeta in [ruta_guardado, ruta_descartados]:
        ruta = os.path.join(carpeta, archivo)
        if os.path.exists(ruta):
            os.remove(ruta)
            print(f"🗑️ Eliminado: {ruta}")



print("\n🔗 Paso 3: Analizando columnas altamente correlacionadas...\n")

def cargar_validos(directorio):
    return [
        f for f in os.listdir(directorio)
        if f.endswith(".csv") and f not in archivos_excluir
    ]

def cargar_dataframe_completo(directorio, lista_archivos):
    dataframes = []
    for archivo in lista_archivos:
        ruta = os.path.join(directorio, archivo)
        if os.path.exists(ruta):
            df = pd.read_csv(ruta)
            df.columns = df.columns.str.strip()
            dataframes.append(df)
    return pd.concat(dataframes, ignore_index=True)

archivos_validos_2 = cargar_validos(ruta_guardado)

df_total_2 = cargar_dataframe_completo(ruta_guardado, archivos_validos_2)

correlation_matrix = df_total_2.corr()

plt.figure(figsize=(23, 20))
sns.heatmap(correlation_matrix, cmap='coolwarm', annot=False)
plt.title("🔗 Matriz de Correlación entre Características (Procesados2)")
plt.tight_layout()
plt.show()

df_numerico = df_total_2.select_dtypes(include=[np.number]).drop(columns=['Label'], errors='ignore')
corr_matrix = df_numerico.corr().abs()

upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
columnas_correlacionadas_2 = set(col for col in upper.columns if any(upper[col] >= 0.8))

print(f"🔍 Columnas correlacionadas encontradas en procesados2 ({len(columnas_correlacionadas_2)}):")
print(columnas_correlacionadas_2)



print("\n✂️ Paso 4: Eliminando columnas correlacionadas de los archivos en procesados2...\n")
columnas_a_eliminar_extra = {'CWE Flag Count', 'min_seg_size_forward', 'Inbound'}
columnas_correlacionadas_2.update(columnas_a_eliminar_extra)

for carpeta in [ruta_guardado]:
    for archivo in cargar_validos(carpeta):
        ruta = os.path.join(carpeta, archivo)
        df = pd.read_csv(ruta)
        df = df.drop(columns=columnas_correlacionadas_2, errors='ignore')
        df.to_csv(ruta, index=False)
        print(f"✅ Guardado limpio en procesados2: {ruta}")



print("\n✂️ Paso 5: Eliminando columnas correlacionadas de los archivos en procesados3...\n")

for carpeta in [ruta_descartados]:
    for archivo in cargar_validos(carpeta):
        ruta = os.path.join(carpeta, archivo)
        df = pd.read_csv(ruta)
        df = df.drop(columns=columnas_correlacionadas_2, errors='ignore')
        df.to_csv(ruta, index=False)
        print(f"✅ Guardado limpio en procesados3: {ruta}")

    df_total_2_limpio = cargar_dataframe_completo(ruta_guardado, cargar_validos(ruta_guardado))

    correlation_matrix_limpia = df_total_2_limpio.corr()

    plt.figure(figsize=(16, 12))
    sns.heatmap(correlation_matrix_limpia, cmap='coolwarm', annot=False)
    plt.title("🔗 Matriz de Correlación (después de eliminar columnas)")
    plt.tight_layout()
    plt.show()



print("\n🔁 Paso 6: Reindexando etiquetas en procesados2 y procesados3...\n")
etiquetas_actuales = set()


for carpeta in [ruta_guardado, ruta_descartados]:
    for archivo in cargar_validos(carpeta):
        df = pd.read_csv(os.path.join(carpeta, archivo))
        if "Label" in df.columns:
            etiquetas_actuales.update(df["Label"].unique())

etiquetas_actuales = sorted(int(e) for e in etiquetas_actuales if pd.api.types.is_number(e))
mapeo_nuevo_label = {old: new for new, old in enumerate(etiquetas_actuales)}

print("📋 Mapeo de etiquetas:")
for old, new in mapeo_nuevo_label.items():
    print(f"  {old} → {new}")

for carpeta in [ruta_guardado, ruta_descartados]:
    for archivo in cargar_validos(carpeta):
        ruta = os.path.join(carpeta, archivo)
        df = pd.read_csv(ruta)
        if "Label" in df.columns:
            df["Label"] = df["Label"].map(mapeo_nuevo_label).astype(int)
      
        if 'Unnamed: 0' in df.columns:
            df = df.drop(columns=['Unnamed: 0'])

        df.to_csv(ruta, index=False)
        print(f"✅ Etiquetas reindexadas y columna 'Unnamed: 0' eliminada: {archivo} en {carpeta}")
        
        
        
        
        
        
        
print("\n🎉 Proceso finalizado correctamente.")