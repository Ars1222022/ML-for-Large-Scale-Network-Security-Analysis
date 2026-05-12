
# NETWORK SECURITY ML MODEL
Skapad: 2026-03-06 09:37:47

## Modellbeskrivning
Nätverksintrångsdetektering - klassificerar trafik som normal eller attack

## Prestanda
- Noggrannhet: 99.90%
- Precision (attacker): 100.00%
- Recall (attacker): 99.04%
- F1-score: 99.52%

## Filer i denna mapp
- network_intrusion_model.pkl : Den tränade modellen
- feature_columns.pkl : Lista över kolumner som modellen förväntar sig
- model_metadata.pkl : Information om modellen och dess prestanda

## Användning i produktion
1. Ladda modellen: joblib.load('network_intrusion_model.pkl')
2. Ladda feature columns: joblib.load('feature_columns.pkl')
3. Förbered ny data med exakt samma kolumner
4. Gör prediktioner med model.predict(X_new)
