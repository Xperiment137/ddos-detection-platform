import os
import numpy as np
import pandas as pd
import torch
import matplotlib.pyplot as plt
import joblib
import seaborn as sns
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from xgboost import XGBClassifier
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

X_df = df.drop(columns=['Label'])



X = df.drop(columns=['Label']).values
y = df['Label'].values
print("Distribución de clases:\n", pd.Series(y).value_counts())



X = np.array(X, dtype=np.float32)
y = np.array(y, dtype=np.int64)

k_folds = 5
skf = StratifiedKFold(n_splits=k_folds, shuffle=True, random_state=42)


mejores_parametros = {
    'n_estimators': 600, 
    'max_depth': 6, 
    'learning_rate': 0.01,  
    'gamma': 0.1,  
    'colsample_bytree': 0.7, 
    'subsample': 0.75, 
    'reg_alpha': 0.1,  
    'reg_lambda': 0.1,  
    'min_child_weight': 10,  
    'objective': "multi:softmax",
    'num_class': len(np.unique(y)),
    'eval_metric': "mlogloss",
    'tree_method': "hist",  
    'device': "cuda" if dispositivo == "cuda" else "cpu",
    'early_stopping_rounds': 100,  
}

accuracy_scores = []
train_losses_folds = []
val_losses_folds = []

for fold, (train_idx, test_idx) in enumerate(skf.split(X, y)):
    print(f"\n🔄 Fold {fold+1}/{k_folds}...")

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    modelo = XGBClassifier(**mejores_parametros)
    modelo.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    y_pred = modelo.predict(X_test)
    acc = accuracy_score(y_test, y_pred) * 100
    accuracy_scores.append(acc)

    print(f"✅ Accuracy en Fold {fold+1}: {acc:.2f}%")
    print(classification_report(y_test, y_pred))

    cm = confusion_matrix(y_test, y_pred)

    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=np.unique(y), yticklabels=np.unique(y))
    plt.xlabel("Predicción")
    plt.ylabel("Real")
    plt.title(f"Matriz de Confusión - Fold {fold+1}")


    resultados = modelo.evals_result()
    train_losses_folds.append(resultados["validation_0"]["mlogloss"])
    val_losses_folds.append(resultados["validation_0"]["mlogloss"])

    joblib.dump(modelo, f"modelo_fold_{fold+1}.pkl")
    print(f"✅ Modelo guardado como modelo_fold_{fold+1}.pkl")

max_epochs = max([len(loss) for loss in train_losses_folds])


train_losses_folds = [loss + [np.nan] * (max_epochs - len(loss)) for loss in train_losses_folds]
val_losses_folds = [loss + [np.nan] * (max_epochs - len(loss)) for loss in val_losses_folds]

mean_train_loss = np.nanmean(train_losses_folds, axis=0)
mean_val_loss = np.nanmean(val_losses_folds, axis=0)

plt.figure(figsize=(10, 6))

for fold in range(k_folds):
    plt.plot(train_losses_folds[fold], label=f"Train Loss Fold {fold+1}")
    plt.plot(val_losses_folds[fold], label=f"Validation Loss Fold {fold+1}")

plt.plot(mean_train_loss, label="Avg Train Loss", linestyle="--", color="black", linewidth=2)
plt.plot(mean_val_loss, label="Avg Validation Loss", linestyle="--", color="red", linewidth=2)

plt.xlabel("Epochs")
plt.ylabel("Log Loss")
plt.title("Evolución de la Pérdida de Entrenamiento y Validación por Fold")
plt.legend()
plt.grid(True)
plt.show()

modelo.save_model("E:\\Ataques DDOS\\saves\\xgboost_model.json")

