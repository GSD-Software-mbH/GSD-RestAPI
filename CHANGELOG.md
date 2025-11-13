## 0.1.42
* Multi-Request bugfix when request fails because of a invalid session

## 0.1.41
* Sync 'getSyncObjectsOfClass' maxRecords Parameter möglich

## 0.1.40
* v2/login/secure entfernen => nur noch v2/login möglich

## 0.1.39
* Sync Objektabfrage Body Bugfix

## 0.1.38
* Sync-Objekte und Struktur einfügen

## 0.1.37
* Revision und NextMarker Parameter zu 'getSyncObjectsOfClass' hinzufügen

## 0.1.36
* Tests für RestApiDOCUframeConfig und RestApiDOCUframeCallbacks Klassen hinzugefügt
* `executeWithoutBuffering` Funktion implementiert für direkte API-Aufrufe ohne Buffering

## 0.1.35
* Modulare Architektur mit separaten Konfigurationsobjekten implementiert
* RestApiDOCUframeConfig-Klasse fÃ¼r zentrale Konfigurationsverwaltung hinzugefÃ¼gt
* RestApiDOCUframeCallbacks-Klasse fÃ¼r typ-sicheres Event-Management implementiert
* RestApiConfig als Basisklasse fÃ¼r grundlegende API-Konfiguration erstellt
* RestApiCallbacks als Basis-Callback-System fÃ¼r grundlegende Events implementiert
* Konstruktor-Parameter auf config- und callbacks-Objekte umgestellt
* Verbesserte Testbarkeit durch isolierte Konfiguration und Event-Logik
* Bessere Wartbarkeit durch getrennte Verantwortlichkeiten
* Sync Abfragen implementiert
* Custom Abfragen implementiert

## 0.1.34
* Web: Upload file bugfix

## 0.1.33
* Getter und Setter fÃ¼r Multi-Request Modus und Buffer grÃ¶ÃŸe

## 0.1.32
* Multi-Request-System, mehrere API-Aufrufe  bÃ¼ndeln und in einer einzigen HTTP-Anfrage zu senden.

## 0.1.31
* ACLEntry LicenseLevel kann nullable ein

## 0.1.30
* lint fehlerbehebung

## 0.1.29
* onSessionIdChanged Callback umbennen

## 0.1.28
* RestAPIUploadFile bytes als Uint8List
* Firebase Performance mit universelles Metric objekt erstetzt

## 0.1.27
* RestAPIUploadFile einbauen | Refaktor, Entfernen von unnÃ¶tigen packages
* CI-Update - Automatisches Code Fix, formatieren und analysieren

## 0.1.26
* MDM 2.0 Version unterstÃ¼tzen | Bugfix

## 0.1.25
* Lint fehler beheben
* MDM 2.0 Version unterstÃ¼tzen

## 0.1.24
* Parameter hinzufÃ¼gen, um hochgeladene Dateien zu benennen
* Log Callback hinzufÃ¼gen

## 0.1.23
* Zwei Faktor Authentifizierung: 2FA Parameter in Header und Body Ã¼bergeben

## 0.1.21
* Zwei Faktor Authentifizierung: Event bei fehlenden 2FA Token auslÃ¶sen

## 0.1.20
* Aktionen bei der patchMail Funktion mit eingebaut

## 0.1.19
* Demo Link hinzufÃ¼gen in README.md
* CI-Update - Automatisches Formatieren vom Code bevor es in pub.dev hochgeladen wird.

## 0.1.18
* Zwei Faktor Authentifizierung funktionen hinzufÃ¼gen
* UnnÃ¶tige extensions entfernen

## 0.1.17
* CI-Update - Ã¼berprÃ¼fen das die CHANGELOG.md einen Eintrag fÃ¼r die nÃ¤chste Version enthÃ¤lt.
* CI-Update - Automatisches Formatieren vom Code bevor es in pub.dev hochgeladen wird.

## 0.1.16
* Datei-Upload Bugfix

## 0.1.15
* Beispiel Bugfix
* CI-Update

## 0.1.13
* CI-Update - Beispiel App mit erstellen

## 0.1.12
* Entfernen von nicht benÃ¶tigten parameter aus `getUploadFile`

## 0.1.11
* Datei-Upload-Response Bugfix

## 0.1.10
* Asynchroner Datei-Upload-Controller fÃ¼r verbesserte Upload-Verwaltung hinzugefÃ¼gt
* `RestAPIFileUploadController` Klasse zur Ãœberwachung des Upload-Fortschritts eingefÃ¼hrt
* `uploadFileWithController()` Methode hinzugefÃ¼gt um Uploads zu starten und sofort Upload-ID zu erhalten
* Upload-Abbruch-FunktionalitÃ¤t implementiert
* Verbesserte Fehlerbehandlung und Status-Verfolgung fÃ¼r Datei-Uploads
* Umfassende deutsche Dokumentation fÃ¼r Upload-Controller hinzugefÃ¼gt
* Upload-Methoden refaktoriert mit verbesserter Trennung der Verantwortlichkeiten
* `getUploadFile()` Methode zum Abrufen von Upload-Metadaten hinzugefÃ¼gt

## 0.1.9
* Pakete aktualisiert

## 0.1.8
* Lint-Fehler behoben

## 0.1.7
* AbhÃ¤ngigkeiten aktualisiert
* Beispiel-App hinzugefÃ¼gt
* Pub Points Status verbessert

## 0.1.1
* Erste VerÃ¶ffentlichung des GSD RestAPI Pakets
* Umfassende REST API FunktionalitÃ¤t fÃ¼r Flutter-Anwendungen
* Automatisches Session-Management mit automatischer Erneuerung
* UnterstÃ¼tzung fÃ¼r alle HTTP-Methoden (GET, POST, PUT, PATCH, DELETE)
* RSA- und AES-VerschlÃ¼sselung fÃ¼r sichere Authentifizierung
* GerÃ¤tespezifische Authentifizierung und Verwaltung
* Firebase Performance Monitoring Integration
* Konfigurierbare SSL-Zertifikat-Validierung
* Timeout-Konfiguration fÃ¼r Verbindung und Antworten
* E-Mail-FunktionalitÃ¤t (erstellen, bearbeiten, senden)
* Kalender-Verwaltung mit Serien-UnterstÃ¼tzung
* Datei-Upload/Download-Funktionen
* Umfassende Fehlerbehandlung mit spezifischen Exceptions
* PlattformÃ¼bergreifende UnterstÃ¼tzung (Android, iOS, Web, Windows, macOS, Linux)
* Web-Plattform-UnterstÃ¼tzung mit konditionalen Exporten
* Event-gesteuerte Architektur fÃ¼r Session- und Authentifizierungs-Ãœberwachung
* Professionelle REST API Kommunikation mit sauberer Architektur