# analyze_network_traffic.py
import pandas as pd
import numpy as np
from sqlalchemy import create_engine
import joblib
import os
import sys
from datetime import datetime

# KONFIGURATION
SERVER_NAME = "localhost"  # ?NDRA DETTA!
DATABASE_NAME = "NetworkSecurityML"
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))

print("="*60)
print("ANALYS AV NATVERKSTRAFIK MED ML-MODELL")
print("="*60)

# 1. ANSLUT TILL SQL SERVER
try:
    conn_str = f"mssql+pyodbc://@{SERVER_NAME}/{DATABASE_NAME}?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes"
    engine = create_engine(conn_str)
    print("[1/6] ANSLUTEN TILL SQL SERVER")
except Exception as e:
    print(f"FEL: {e}")
    sys.exit(1)

# 2. LADDA MODELL
try:
    print("[2/6] LADDAR ML-MODELL...")
    model = joblib.load(os.path.join(MODEL_DIR, "network_intrusion_model.pkl"))
    features = joblib.load(os.path.join(MODEL_DIR, "feature_columns.pkl"))
    print(f"      OK - {len(features)} features")
except Exception as e:
    print(f"FEL: {e}")
    sys.exit(1)

# 3. HAMTA DATA
query = """
    SELECT TOP 500
        ntl.LogID, ntl.Protocol, ntl.SourcePort, ntl.DestinationPort,
        ntl.PacketSize, ntl.Duration, ntl.BytesSent, ntl.BytesReceived
    FROM NetworkTrafficLogs ntl
    LEFT JOIN ThreatDetections td ON ntl.LogID = td.LogID
    WHERE td.DetectionID IS NULL
"""
try:
    print("[3/6] HAMTAR DATA...")
    df = pd.read_sql_query(query, engine)
    print(f"      HAMTADE {len(df)} RADER")
    if len(df) == 0:
        print("      INGEN NY DATA - AVSLUTAR")
        sys.exit(0)
except Exception as e:
    print(f"FEL: {e}")
    sys.exit(1)

# 4. FORBERED DATA
print("[4/6] FORBEREDER DATA...")
log_ids = df['LogID'].copy()
df_encoded = pd.get_dummies(df.drop('LogID', axis=1), columns=['Protocol'])

for col in features:
    if col not in df_encoded.columns:
        df_encoded[col] = 0

X = df_encoded[features]

# 5. ANALYSERA
print("[5/6] ANALYSERAR...")
preds = model.predict(X)
probs = model.predict_proba(X)

results = pd.DataFrame({
    'LogID': log_ids,
    'Prediction': preds,
    'Confidence': [probs[i][1] if preds[i]==1 else probs[i][0] for i in range(len(preds))],
    'ThreatType': ['Attack' if p==1 else 'Normal' for p in preds],
    'AnomalyScore': 0.0,
    'ProcessedDate': datetime.now()
})

attacks = len(results[results['Prediction']==1])
print(f"      HITTADE {attacks} POTENTIELLA ATTACKER")

# 6. SPARA
print("[6/6] SPARAR I SQL SERVER...")
results.to_sql('ThreatDetections', engine, if_exists='append', index=False)
print(f"      SPARADE {len(results)} RADER")

print("="*60)
print("ANALYS KLAR!")
print(f"TOTALT: {len(results)} | NORMAL: {len(results)-attacks} | ATTACKER: {attacks}")
print("="*60)
