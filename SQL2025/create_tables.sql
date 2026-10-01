-- =====================================================
-- SKRIPT: Skapa alla tabeller för NetworkSecurityML
-- Databas: NetworkSecurityML
-- Beskrivning: Skapar tre tabeller för ML-baserad
--              nätverkssäkerhetsanalys
-- =====================================================

-- =====================================================
-- 0. SKAPA DATABASEN (om den inte redan finns)
-- =====================================================
-- Steg 7 i workshoppen säger att du ska skapa databasen i SSMS.
-- Men om du bara kör det här skriptet (eller kör det i Docker)
-- måste databasen skapas först. Därför gör vi det här - och bara
-- OM den inte redan finns, så du kan köra skriptet flera gånger.
-- =====================================================

IF DB_ID('NetworkSecurityML') IS NULL
BEGIN
    CREATE DATABASE NetworkSecurityML;
    PRINT '✅ Databas NetworkSecurityML skapad';
END
ELSE
BEGIN
    PRINT 'ℹ️  Databas NetworkSecurityML finns redan - hoppar över skapandet';
END
GO

-- Byt till rätt databas
USE NetworkSecurityML;
GO

-- =====================================================
-- 0b. TA BORT GAMLA TABELLER OCH VY (om de finns)
-- =====================================================
-- Det här gör att skriptet går att köra flera gånger.
--
-- VIKTIGT: Ordningen spelar roll!
--   1. Vyn måste tas bort först - den refererar till båda tabellerna.
--   2. Sedan ThreatDetections - den har en FRÄMMANDE NYCKEL till
--      NetworkTrafficLogs, så den måste tas bort INNAN den tabellen.
--   3. Till sist NetworkTrafficLogs och SecurityMetrics.
-- Tagen i fel ordning får du felet:
--   "Could not drop object 'dbo.NetworkTrafficLogs' because it is
--    referenced by a FOREIGN KEY constraint."
-- =====================================================

-- 1. Vyn först (den refererar till NetworkTrafficLogs och ThreatDetections)
IF OBJECT_ID('dbo.vw_TrafficAnalysis', 'V') IS NOT NULL
    DROP VIEW dbo.vw_TrafficAnalysis;
GO

-- 2. Sedan tabellen som har främmande nyckel (måste före NetworkTrafficLogs)
IF OBJECT_ID('dbo.ThreatDetections', 'U') IS NOT NULL
    DROP TABLE dbo.ThreatDetections;
GO

-- 3. Till sist de övriga tabellerna
IF OBJECT_ID('dbo.SecurityMetrics', 'U') IS NOT NULL
    DROP TABLE dbo.SecurityMetrics;
GO

IF OBJECT_ID('dbo.NetworkTrafficLogs', 'U') IS NOT NULL
    DROP TABLE dbo.NetworkTrafficLogs;
GO

-- =====================================================
-- 1. SKAPA TABELL: NetworkTrafficLogs (rådata)
-- =====================================================
-- Denna tabell lagrar all inkommande nätverkstrafik
-- och fungerar som rådata för vår ML-modell
-- =====================================================

-- (Tabellen togs bort i steg 0b ovan, så den finns inte just nu)

CREATE TABLE dbo.NetworkTrafficLogs (
    -- Primärnyckel: auto-inkrementerande ID för varje loggrad
    LogID INT IDENTITY(1,1) PRIMARY KEY,
    
    -- Tidsstämpel för när trafiken registrerades
    Timestamp DATETIME DEFAULT GETDATE(),
    
    -- IP-adresser (varchar(45) rymmer både IPv4 och IPv6)
    SourceIP VARCHAR(45),
    DestinationIP VARCHAR(45),
    
    -- Nätverksprotokoll (TCP, UDP, ICMP, etc.)
    Protocol VARCHAR(10),
    
    -- Portar (0-65535)
    SourcePort INT,
    DestinationPort INT,
    
    -- Trafikdetaljer
    PacketSize INT,              -- Paketstorlek i bytes
    Duration FLOAT,               -- Anslutningstid i sekunder
    BytesSent BIGINT,             -- Skickade bytes
    BytesReceived BIGINT,         -- Mottagna bytes
    
    -- TCP-specifika flaggor (SYN, ACK, FIN, etc.)
    TCPFlags VARCHAR(20),
    
    -- Etikettering: 1 = Attack, 0 = Normal, NULL = oklassificerad
    IsMalicious BIT NULL,
    
    -- Var etiketten kommer ifrån (t.ex. 'Training', 'Manual', 'ML_Prediction')
    LabelSource VARCHAR(50),
    
    -- Begränsningar för att säkerställa giltiga portar
    CONSTRAINT CHK_Ports CHECK (
        SourcePort BETWEEN 0 AND 65535 AND 
        DestinationPort BETWEEN 0 AND 65535
    )
);
GO

-- Skapa index för snabbare sökningar (viktigt för prestanda)
CREATE INDEX IX_NetworkTraffic_Timestamp ON dbo.NetworkTrafficLogs(Timestamp);
CREATE INDEX IX_NetworkTraffic_IP ON dbo.NetworkTrafficLogs(SourceIP, DestinationIP);
CREATE INDEX IX_NetworkTraffic_IsMalicious ON dbo.NetworkTrafficLogs(IsMalicious);
GO

PRINT '✅ Tabell NetworkTrafficLogs skapad';
GO

-- =====================================================
-- 2. SKAPA TABELL: ThreatDetections (ML-resultat)
-- =====================================================
-- Denna tabell lagrar resultaten från vår ML-modell
-- Varje rad motsvarar en prediktion på en loggrad
-- =====================================================

-- (Tabellen togs bort i steg 0b ovan, så den finns inte just nu)

CREATE TABLE dbo.ThreatDetections (
    -- Primärnyckel
    DetectionID INT IDENTITY(1,1) PRIMARY KEY,
    
    -- Koppling till originaldatan (foreign key)
    LogID INT NOT NULL,
    
    -- ML-resultat
    Prediction INT NOT NULL,        -- 1 = Skadlig, 0 = Normal
    Confidence FLOAT,                -- Modellens säkerhet (0-1)
    ThreatType VARCHAR(50),          -- Typ av hot (DDoS, Port Scan, etc.)
    AnomalyScore FLOAT,              -- Poäng från anomalidetektering
    
    -- När prediktionen gjordes
    ProcessedDate DATETIME DEFAULT GETDATE(),
    
    -- Analytikerfeedback (för att förbättra modellen)
    ReviewedByAnalyst BIT DEFAULT 0,  -- Har analytiker granskat?
    AnalystFeedback VARCHAR(255),     -- Analytikerns kommentar
    
    -- Skapa foreign key-relation till NetworkTrafficLogs
    CONSTRAINT FK_ThreatDetections_NetworkTrafficLogs 
        FOREIGN KEY (LogID) REFERENCES dbo.NetworkTrafficLogs(LogID)
);
GO

-- Skapa index för snabbare joins och filtrering
CREATE INDEX IX_ThreatDetections_LogID ON dbo.ThreatDetections(LogID);
CREATE INDEX IX_ThreatDetections_ProcessedDate ON dbo.ThreatDetections(ProcessedDate);
CREATE INDEX IX_ThreatDetections_Reviewed ON dbo.ThreatDetections(ReviewedByAnalyst);
GO

PRINT '✅ Tabell ThreatDetections skapad';
GO

-- =====================================================
-- 3. SKAPA TABELL: SecurityMetrics (aggregerad statistik)
-- =====================================================
-- Denna tabell lagrar sammanställd statistik för Power BI
-- Uppdateras automatiskt eller via Python-skript
-- =====================================================

-- (Tabellen togs bort i steg 0b ovan, så den finns inte just nu)

CREATE TABLE dbo.SecurityMetrics (
    -- Primärnyckel
    MetricID INT IDENTITY(1,1) PRIMARY KEY,
    
    -- Tidpunkt för statistiken
    Date DATE DEFAULT CAST(GETDATE() AS DATE),
    Hour INT DEFAULT DATEPART(HOUR, GETDATE()),
    
    -- Räknevärden
    TotalTraffic INT,                -- Totalt antal loggar
    MaliciousTraffic INT,             -- Antal detekterade hot
    NormalTraffic INT,                -- Antal normal trafik
    
    -- Kvalitetsmått
    AvgConfidence FLOAT,              -- Genomsnittlig konfidens för prediktioner
    
    -- Metadata
    TopAttackType VARCHAR(50),        -- Vanligaste attacktypen
    UniqueSourceIPs INT,               -- Antal unika käll-IPer
    UniqueDestinationIPs INT           -- Antal unika destinations-IPer
);
GO

-- Skapa index för tidsbaserade frågor
CREATE INDEX IX_SecurityMetrics_Date ON dbo.SecurityMetrics(Date, Hour);
GO

PRINT '✅ Tabell SecurityMetrics skapad';
GO

-- =====================================================
-- 4. SKAPA EN VY (VIEW) för enkel analys
-- =====================================================
-- En vy är som en sparad fråga som gör det enklare
-- att hämta ihopkopplad data i Power BI
-- =====================================================

-- (Vyn togs bort i steg 0b ovan, så den finns inte just nu)

CREATE VIEW dbo.vw_TrafficAnalysis AS
SELECT 
    -- Fält från NetworkTrafficLogs
    ntl.LogID,
    ntl.Timestamp,
    ntl.SourceIP,
    ntl.DestinationIP,
    ntl.Protocol,
    ntl.SourcePort,
    ntl.DestinationPort,
    ntl.PacketSize,
    ntl.Duration,
    ntl.BytesSent,
    ntl.BytesReceived,
    ntl.IsMalicious as ActualLabel,  -- Den sanna etiketten (om känd)
    
    -- Fält från ThreatDetections
    td.Prediction,
    td.Confidence,
    td.ThreatType,
    td.AnomalyScore,
    td.ProcessedDate as DetectionDate,
    
    -- Klassificeringsresultat (för utvärdering)
    CASE 
        WHEN td.Prediction = 1 AND ntl.IsMalicious = 1 THEN 'TP'  -- True Positive (rätt identifierat hot)
        WHEN td.Prediction = 1 AND ntl.IsMalicious = 0 THEN 'FP'  -- False Positive (falskt larm)
        WHEN td.Prediction = 0 AND ntl.IsMalicious = 1 THEN 'FN'  -- False Negative (missat hot)
        WHEN td.Prediction = 0 AND ntl.IsMalicious = 0 THEN 'TN'  -- True Negative (rätt identifierad normal)
        ELSE 'Unknown'
    END as ClassificationResult
    
FROM dbo.NetworkTrafficLogs ntl
LEFT JOIN dbo.ThreatDetections td ON ntl.LogID = td.LogID;
GO

PRINT '✅ Vy vw_TrafficAnalysis skapad';
GO

-- =====================================================
-- 5. SKAPA LITE TESTDATA (VALFRITT)
-- =====================================================
-- Detta lägger in några testrader så att du har data
-- att jobba med direkt. Kommentera bort om du inte vill ha testdata.
-- =====================================================

PRINT '🔄 Lägger in testdata...';
GO

-- Lägg in 20 testrader i NetworkTrafficLogs
INSERT INTO dbo.NetworkTrafficLogs (
    SourceIP, DestinationIP, Protocol, SourcePort, DestinationPort,
    PacketSize, Duration, BytesSent, BytesReceived, TCPFlags, IsMalicious
)
VALUES 
-- Normal trafik (IsMalicious = 0)
('192.168.1.10', '142.250.185.46', 'TCP', 54321, 443, 1420, 2.5, 45000, 120000, 'ACK', 0),
('192.168.1.15', '151.101.1.69', 'TCP', 33456, 80, 1480, 1.8, 32000, 85000, 'PSH,ACK', 0),
('10.0.0.5', '8.8.8.8', 'UDP', 12345, 53, 512, 0.3, 120, 350, 'N/A', 0),
('192.168.1.20', '204.79.197.200', 'TCP', 44567, 443, 1400, 3.2, 67000, 210000, 'ACK', 0),
('172.16.0.8', '13.107.42.14', 'TCP', 37890, 80, 1460, 2.1, 28000, 76000, 'SYN,ACK', 0),

-- Skadlig trafik (IsMalicious = 1)
('10.0.0.100', '192.168.1.1', 'TCP', 6666, 22, 60, 0.05, 200, 50, 'SYN', 1),
('45.33.22.11', '192.168.1.50', 'TCP', 44321, 3389, 120, 0.1, 500, 80, 'SYN', 1),
('77.88.55.33', '192.168.1.100', 'TCP', 55555, 445, 80, 0.08, 300, 40, 'SYN', 1),
('31.13.79.246', '192.168.1.200', 'TCP', 12345, 80, 40, 0.02, 1000, 10, 'SYN', 1),
('66.220.144.0', '192.168.1.150', 'UDP', 33456, 53, 1500, 2.0, 1000000, 500, 'N/A', 1),

-- Fler normala
('192.168.1.25', '216.58.211.46', 'TCP', 49152, 443, 1440, 2.8, 52000, 145000, 'FIN,ACK', 0),
('192.168.1.30', '104.16.133.229', 'TCP', 50123, 80, 1490, 1.5, 41000, 93000, 'ACK', 0),
('10.0.0.15', '1.1.1.1', 'UDP', 22222, 53, 480, 0.4, 150, 420, 'N/A', 0),

-- Fler skadliga
('185.130.5.133', '192.168.1.10', 'TCP', 31337, 22, 55, 0.03, 150, 30, 'SYN', 1),
('91.219.236.10', '192.168.1.20', 'TCP', 65000, 3389, 90, 0.07, 400, 60, 'SYN', 1),
('194.54.14.0', '192.168.1.30', 'TCP', 8080, 445, 70, 0.04, 250, 35, 'SYN', 1),
('103.56.78.9', '192.168.1.40', 'TCP', 9999, 1433, 110, 0.09, 600, 90, 'SYN', 1),

-- Blandat
('192.168.1.35', '52.113.194.132', 'TCP', 54321, 443, 1410, 2.2, 49000, 135000, 'PSH,ACK', 0),
('192.168.1.40', '172.217.18.4', 'TCP', 33567, 80, 1470, 1.9, 36000, 89000, 'ACK', 0),
('8.8.4.4', '192.168.1.5', 'UDP', 53, 33456, 520, 0.5, 200, 500, 'N/A', 1);  -- DNS amplification attack

PRINT '✅ Testdata insatt (20 rader)';
GO

-- Visa vad som skapats
PRINT '';
PRINT '=========================================';
PRINT '📊 SAMMANFATTNING - Tabeller skapade:';
PRINT '=========================================';
SELECT 'NetworkTrafficLogs' as TabellNamn, COUNT(*) as AntalRader FROM dbo.NetworkTrafficLogs
UNION ALL
SELECT 'ThreatDetections', COUNT(*) FROM dbo.ThreatDetections
UNION ALL
SELECT 'SecurityMetrics', COUNT(*) FROM dbo.SecurityMetrics;
GO

PRINT '';
PRINT '✅ Alla tabeller har skapats! Du är redo att gå vidare till nästa steg.';
GO