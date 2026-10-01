# analyze_network_traffic.py
import pandas as pd
import numpy as np
from sqlalchemy import create_engine
import joblib
import os
import sys
from datetime import datetime

# KONFIGURATION
# ---------------------------------------------------------------
# SERVER_NAME: Ändra här om din SQL Server heter något annat
#              än "localhost" (t.ex. DESKTOP-ABC123).
#              Kan även sättas med miljövariabeln SQL_SERVER.
# ---------------------------------------------------------------
SERVER_NAME = "localhost"  # ÄNDRA DETTA!
DATABASE_NAME = "NetworkSecurityML"
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))

# Miljövariabler (valfritt - används t.ex. med Docker).
# Om de inte sätts används värdena ovan, precis som tidigare.
SERVER_NAME = os.environ.get("SQL_SERVER", SERVER_NAME)
DATABASE_NAME = os.environ.get("SQL_DATABASE", DATABASE_NAME)

# SQL_USER/SQL_PASSWORD: lämnar du dem tomma används Windows-autentisering
# (det vanligaste fallet på en egen dator). Fyller du i dem används
# SQL-inloggning - det krävs t.ex. för SQL Server i Docker.
SQL_USER = os.environ.get("SQL_USER", "")
SQL_PASSWORD = os.environ.get("SQL_PASSWORD", "")

print("="*60)
print("ANALYS AV NATVERKSTRAFIK MED ML-MODELL")
print("="*60)
print(f"Server: {SERVER_NAME} | Database: {DATABASE_NAME}")
print(f"Inloggning: {'SQL-inloggning (' + SQL_USER + ')' if SQL_USER else 'Windows-autentisering'}")

# 1. ANSLUT TILL SQL SERVER
try:
    if SQL_USER and SQL_PASSWORD:
        # SQL-inloggning (t.ex. mot Docker-container)
        conn_str = (
            f"mssql+pyodbc://{SQL_USER}:{SQL_PASSWORD}@{SERVER_NAME}/{DATABASE_NAME}"
            f"?driver=ODBC+Driver+17+for+SQL+Server&TrustServerCertificate=yes"
        )
    else:
        # Windows-autentisering (standard, funkar direkt på Windows)
        conn_str = (
            f"mssql+pyodbc://@{SERVER_NAME}/{DATABASE_NAME}"
            f"?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes"
        )
    engine = create_engine(conn_str)
    # Testa anslutningen direkt så vi får ett tydligt felmeddelande
    with engine.connect() as test_conn:
        test_conn.exec_driver_sql("SELECT 1")
    print("[1/6] ANSLUTEN TILL SQL SERVER")
except Exception as e:
    print(f"FEL: {e}")
    # Observera: raderna nedan ar medvetet skrivna UTAN svenska
    # tecken (a/ae/o). Console-kodningen pa Windows ar inte
    # gar att stodja dem, och da blir hjalptexten olaglig.
    print("\nKontrollera att:")
    print("  1. SQL Server ar igang")
    print(f"  2. Databasen '{DATABASE_NAME}' finns (kor create_tables.sql)")
    print(f"  3. Servernamnet '{SERVER_NAME}' stemmer")
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
