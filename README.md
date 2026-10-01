# Steg 9–10: Maskininlärning för nätverkssäkerhet

Ett system som upptäcker nätverksattacker med ML. Steg 9–10 av en workshop på 12 steg.

**Flödet:**

```
Nätverkstrafik ──► SQL Server ──► ML-modell ──► ThreatDetections ──► Power BI
   (inmatning)       (lagret)      (analysen)      (resultatet)       (visningen)
```

**Innehåll:** [Vad gör vi](#1-vad-gör-vi) · [Filer](#2-filer) · [Versionerna](#3-versionerna-viktigast) · [Steg 8](#4-steg-8--databasen) · [Steg 9](#5-steg-9--modellen) · [Steg 10](#6-steg-10--analysen) · [Felsökning](#7-felsökning) · [Frågor och svar](#8-frågor-och-svar) · [Bilaga](#9-bilaga-valfritt)

---

## 1. Vad gör vi?

| | |
|---|---|
| **Vad** | Tränar en modell som skiljer normal trafik från attacker, kör den mot en databas, och sparar resultaten. |
| **Varför** | En analytiker kan inte granska tusentals händelser manuellt. Modellen sorterar ut de misstänkta på sekunder. |
| **Hur** | Steg 8 (databas) → steg 9 (träna) → steg 10 (analys) → Power BI (visa). |

Modellen tittar på **9 egenskaper** per händelse och svarar `1` = attack, `0` = normal.

---

## 2. Filer

| Fil | Steg | Vad den gör |
|---|---|---|
| `create_tables.sql` | 8 | Skapar databasen, 3 tabeller, 1 vy + 20 testrader |
| `NetworkSecurity_Training.ipynb` | 9 | Tränar modellen i Colab |
| `network_model/*.pkl` | 9 | Den tränade modellen + dess feature-lista |
| `network_model/analyze_network_traffic.py` | 10 | Kör analysen mot databasen |
| `network_model/run_ml_analysis.ps1` | 10 | Installerar paket och kör skriptet |
| `network_model/requirements.txt` | 10 | Exakta paketversioner |
| `NetworkSecurityReportPowerBI.pbix` | 11 | Power BI-rapporten |

---

## 3. Versionerna (viktigast)

| | |
|---|---|
| **Vad** | `requirements.txt` innehåller **testade** versioner: `numpy==2.4.6`, `scikit-learn==1.6.1` |
| **Varför** | Modellen (`.pkl`) är tränad i Colab, som använder numpy 2.x. En `.pkl`-fil fryser också de bibliotek den skapades med. |
| **Hur** | Installera exakt som i filen. Ändra inte versionerna utan att träna om modellen. |

Med fel numpy får du:

```
ModuleNotFoundError: No module named 'numpy._core'
```

Det är det vanligaste felet. **Lösningen är att uppgradera, inte nedgradera.**

---

## 4. Steg 8 – Databasen

| | |
|---|---|
| **Vad** | Skapar databasen `NetworkSecurityML` med 3 tabeller och 1 vy. |
| **Varför** | Rådata och ML-resultat måste sparas någonstans, i ett format både Python och Power BI kan läsa. |
| **Hur** | Öppna SSMS → **File → Open → File…** → välj `create_tables.sql` → tryck **F5**. |

**Vad som skapas:**

| Objekt | Innehåll |
|---|---|
| `NetworkTrafficLogs` | Rå trafik – inmatningen till modellen |
| `ThreatDetections` | ML-resultat – vad modellen tyckte |
| `SecurityMetrics` | Statistik för Power BI |
| `vw_TrafficAnalysis` | Vy som slår ihop de två första och räknar TP/FP/FN/TN |

**Du ska se** i meddelanderutan:

```
✅ Databas NetworkSecurityML skapad
✅ Tabell NetworkTrafficLogs skapad
✅ Tabell ThreatDetections skapad
✅ Tabell SecurityMetrics skapad
✅ Vy vw_TrafficAnalysis skapad
✅ Testdata insatt (20 rader)
```

**Verifiera:**

```sql
USE NetworkSecurityML;
SELECT COUNT(*) AS AntalRader FROM NetworkTrafficLogs;
```

Svar: `20`

> Skriptet går att köra flera gånger. Det raderar dock all data i tabellerna.

---

## 5. Steg 9 – Modellen

> **Har du redan `network_model/*.pkl`?** Hoppa då över steget – filerna finns i mappen.

| | |
|---|---|
| **Vad** | Tränar en Random Forest (100 träd) på 5 000 simulerade trafikrader. |
| **Varför** | Vi har ingen riktig attackdata, så vi skapar realistisk data med kända regler för vad som är en attack. |
| **Hur** | Ladda upp `NetworkSecurity_Training.ipynb` på [colab.research.google.com](https://colab.research.google.com) och kör de 6 cellerna (**Shift+Enter**). |

**Cellerna:**

| Cell | Gör |
|---|---|
| 1 | Importerar bibliotek |
| 2 | Skapar 5 000 rader simulerad trafik |
| 3 | Kodar om Protocol till siffror, delar 80/20 i trän/test |
| 4 | Tränar Random Forest med 100 träd |
| 5 | Utvärderar modellen |
| 6 | Sparar till `.pkl` + zip |

**Måtten i cell 5:**

| Mått | Betyder | Vårt värde |
|---|---|---|
| **Accuracy** | Hur ofta modellen har rätt | 99,9 % |
| **Precision** | Av de som flaggades, hur många var verkliga attacker? | 100 % |
| **Recall** | Av alla verkliga attacker, hur många hittades? | 99,0 % |
| **F1** | Balansen mellan dem | 99,5 % |

> ⚠️ Siffrorna är nästan perfekta **eftersom träningsdatan är syntetisk** – vi skapade attackerna själva efter regler ("port 22 = attack"). I verkligheten är noggrannheten lägre. Det är så här övningsprojekt fungerar.

**Kör om** och packa upp `network_model.zip` till `SQL2025/network_model/`.

### 5.1 Träna lokalt i VS Code istället

| | |
|---|---|
| **Vad** | Notebooken har **2 rader** som kräver Colab. Resten är vanlig Python. |
| **Varför** | Funkar fint att köra lokalt om du vill slippa Colab. Testat: ger **samma accuracy (0,999) och samma features**. |
| **Hur** | Se nedan. |

```powershell
pip install pandas==2.2.3 numpy==2.4.6 scikit-learn==1.6.1 joblib==1.4.2
pip install matplotlib seaborn
```

1. Öppna notebooken i VS Code.
2. **Cell 1** – radera `from google.colab import files`
3. Kör cell **2, 3, 4, 5** som vanligt.
4. **Cell 6** – radera de två sista raderna:
   ```python
   from google.colab import files        # RADERA
   files.download('network_model.zip')   # RADERA
   ```
5. Packa upp `network_model.zip` som skapades i mappen du öppnade.

> Kör alltid cellerna 1 → 6 i ordning. Ändrar du cell 2 måste du köra om 3, 4 och 5.

---


## 6. Steg 10 – Analysen

| | |
|---|---|
| **Vad** | Läser nya rader ur databasen, gör prediktioner, sparar i `ThreatDetections`. |
| **Varför** | Detta kopplar ihop modellen med databasen – så analyser körs automatiskt när ny trafik kommer in. |
| **Hur** | Sätt servernamnet, kör `run_ml_analysis.ps1`, svara `j`. |

### 6.1 Sätt servernamnet

Öppna `analyze_network_traffic.py`, rad 16:

```python
SERVER_NAME = "localhost"  # ÄNDRA DETTA!
```

- `localhost`? → **Lämna som det är**
- `DESKTOP-ABC123`? → byt ut

Servernamnet står i SSMS i rutan **Servernamn** när du ansluter.

### 6.2 Kör skriptet

I VS Code: **Terminal → New Terminal**

```powershell
cd SQL2025\network_model
.\run_ml_analysis.ps1
```

Blir det fel om att PowerShell körs:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_ml_analysis.ps1
```

Skriptet gör 6 kontroller: Python finns → `requirements.txt` → installera paket → Python-skriptet finns → modellfilerna finns → frågar om servernamn och om du vill köra.

### 6.3 Läs utskriften

```
[1/6] ANSLUTEN TILL SQL SERVER
[2/6] LADDAR ML-MODELL...   OK - 9 features
[3/6] HAMTAR DATA...        HAMTADE 20 RADER
[5/6] ANALYSERAR...         HITTADE 7 POTENTIELLA ATTACKER
[6/6] SPARAR I SQL SERVER... SPARADE 20 RADER
TOTALT: 20 | NORMAL: 13 | ATTACKER: 7
```

| Rad | Betyder |
|---|---|
| `9 features` | Rätt modell laddad |
| `HAMTADE n` | n oanalyserade rader hittades |
| `HITTADE n` | n av dem klassades som attacker |

### 6.4 Verifiera i SSMS

```sql
USE NetworkSecurityML;
SELECT ClassificationResult, COUNT(*) AS Antal
FROM dbo.vw_TrafficAnalysis GROUP BY ClassificationResult;
```

| Kod | Betyder |
|---|---|
| `TP` | Attack som hittades ✅ |
| `TN` | Normal som ignorerades korrekt ✅ |
| `FP` | Falsklarm |
| `FN` | Attack som missades ❌ |

### 6.5 Kör om på ny data

Skriptet tar bara rader som **inte redan är analyserade**. Kör det igen → `INGEN NY DATA – AVSLUTAR`. Det är inte ett fel.

Börja om, eller lägg in fler data:

```sql
USE NetworkSecurityML;
DELETE FROM dbo.ThreatDetections;   -- alla rader blir oanalyserade igen
```

---

## 7. Felsökning

### `ModuleNotFoundError: No module named 'numpy._core'`

**Det vanligaste felet.** Modellen är tränad med numpy 2.x, du har 1.x.

```powershell
pip install --upgrade --force-reinstall "numpy==2.4.6" "scikit-learn==1.6.1"
```

Kontrollera: `python -c "import numpy, sklearn; print(numpy.__version__, sklearn.__version__)"` → ska visa `2.4.6 1.6.1`

### `InconsistentVersionWarning: ... version 1.6.1 when using version 1.3.0`

Samma sak – fel scikit-learn-version. Installera enligt ovan.

### `Can't connect to server` / `Login failed`

1. Är SQL Server igång? Kolla i SSMS.
2. Stämmer servernamnet? Prova `localhost`.
3. Är databasen skapad? Kör `create_tables.sql` igen.

### `HAMTADE 0 RADER`

Alla rader är redan analyserade. Inget fel. Kör `DELETE FROM dbo.ThreatDetections;`.

### `FEL: Python ar inte installerat!`

Installera från python.org och kryssa i **"Add Python to PATH"**.

### `ValueError: The feature names should match...`

`feature_columns.pkl` saknas. Packa upp hela `network_model`-mappen igen.

### Power BI visar inga data

Rapporten har **inbäddad data**. Öppna `.pbix` → **Power Query** → välj `NetworkTrafficLogs` och `ThreatDetections` → peka datakällan på din SQL Server → **Home → Refresh** → **Apply**.

---

## 8. Frågor och svar

**Kan jag köra det flera gånger?**
Ja. Både SQL-skriptet och analysen tåler upprepning.

**Raderas min data?**
Om du kör om `create_tables.sql`, ja – det gör `DROP TABLE` först. Steg 10 raderar inget, bara lägger till.

**Vad betyder Confidence?**
Modellens säkerhet. 0,99 = 99 % säker. Låga värden bör granskas manuellt.

**Ändras `IsMalicious` i databasen?**
Nej. Den är "sanningen" och ändras aldrig, så du kan alltid jämföra modellens gissning mot den i vyn.

**Varför kan jag inte köra notebooken lokalt som den är?**
Den är skriven för Colab. Se [5.1](#51-träna-lokalt-i-vs-code-instället) – 2 rader raderas.

**Funkar det på Mac/Linux?**
Databas och Python: ja, via Docker. Power BI Desktop: nej, finns bara för Windows. `run_ml_analysis.ps1` är Windows-specifikt – kör `python analyze_network_traffic.py` direkt istället.

**Behöver jag Docker?**
Nej, helt valfritt – se bilagan.

---


## 9. Bilaga: valfritt

### Docker

SQL Server Express/Developer finns bara för Windows. Med Docker kör du samma databas på Windows, macOS och Linux – och den är enkel att nollställa. **Helt valfritt**, allt ovan fungerar likadant med lokalt installerad SQL Server.

Kräver Docker Desktop och minst 2 GB ledigt minne. Skapa `docker-compose.yml` i `SQL2025/`:

```yaml
services:
  sqlserver:
    image: mcr.microsoft.com/mssql/server:2022-latest
    container_name: networkml-sql
    environment:
      ACCEPT_EULA: "Y"
      MSSQL_SA_PASSWORD: "YourStrong!Passw0rd"
      MSSQL_PID: "Developer"
    ports:
      - "1433:1433"
    volumes:
      - ./create_tables.sql:/init/create_tables.sql:ro
```

```powershell
docker compose up -d
```

Vänta tills loggen säger `SQL Server is now ready for client connections` (30–60 s första gången).

Skapa tabellerna:

```powershell
docker exec -i networkml-sql /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "YourStrong!Passw0rd" -C -i /init/create_tables.sql
```

Kör analysen – i containern fungerar inte Windows-inloggning, så använd SQL-inloggning:

```powershell
$env:SQL_SERVER = "localhost"
$env:SQL_USER = "sa"
$env:SQL_PASSWORD = "YourStrong!Passw0rd"
python analyze_network_traffic.py
```

I SSMS: servernamn `localhost,1433`, autentisering **SQL Server-autentisering**, användarnamn `sa`.

Stäng av: `docker compose down -v` (`-v` raderar även databasen).

### Fler testdata

`create_tables.sql` ger 20 rader, och analysen tar max 500 per körning. Vill du se fler, kör detta i SSMS – det ger 1 000 nya rader (500 normala + 500 attacker):

```sql
USE NetworkSecurityML;

DECLARE @i INT = 0;
WHILE @i < 500
BEGIN
    INSERT INTO dbo.NetworkTrafficLogs
        (SourceIP, DestinationIP, Protocol, SourcePort, DestinationPort,
         PacketSize, Duration, BytesSent, BytesReceived, TCPFlags, IsMalicious)
    VALUES
    (CONCAT('192.168.1.', 10 + (@i % 200)), '142.250.185.46', 'TCP', 49152 + (@i % 1000), 443,
     1400 + (@i % 60), 2.5, 45000, 120000, 'ACK', 0),
    (CONCAT('45.33.', @i % 255, '.', (@i * 7) % 255), '192.168.1.1', 'TCP', 1024 + (@i % 60000), 22,
     55, 0.03, 150, 30, 'SYN', 1);
    SET @i = @i + 1;
END

SELECT COUNT(*) AS TotalaRader FROM dbo.NetworkTrafficLogs;
```

Kör steg 10 igen – den hittar de nya raderna automatiskt.

---

## Sammanfattning

| Steg | Vad | Var |
|---|---|---|
| **8** | Skapa databas, tabeller, vy | `SQL2025/create_tables.sql` + SSMS |
| **9** | Träna modell | `SQL2025/NetworkSecurity_Training.ipynb` |
| **10** | Kör analysen | `SQL2025/network_model/run_ml_analysis.ps1` |
| 11–12 | Power BI-rapport | `SQL2025/NetworkSecurityReportPowerBI.pbix` |

**Det viktigaste:** `requirements.txt` och `.pkl`-filerna måste matcha varandra. Ändra inte versionerna utan att träna om modellen.
