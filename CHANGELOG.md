## 0.1.64
* `RestApiDOCUframeManager.getObjects` Parameter `actions` hinzugefügt um zusätzliche Aktionen auszuführen
* Funktion`RestApiDOCUframeManager.postAction` hinzugefügt um Aktionen direkt auf Objekten auszuführen

## 0.1.63
* `RestApiConfig.debugLogs` Parameter hinzufügen um debugPrint zu aktivieren/deaktivieren

## 0.1.62
* Ändern des `RestApiDOCUframeManager.customRequest` Rückgabewertes zum standart HTTP Response

## 0.1.61
* `RestApiDOCUframeManager.deleteObject` Parameter `moveToRecycler` hinzugefügt

## 0.1.60
* `RestApiDOCUframeManager.deleteFolders` Parameter `notEmpty` hinzugefügt um auch nicht leere Ordner zu löschen

## 0.1.59
* `RestApiDOCUframeManager.postMailSend` Parameter `sendAssignReceiver` hinzugefügt

## 0.1.58
* `RestApiDOCUframeManager.getDocumentPaths` `extended` Parameter hinzugefügt, für erweiterte Informationen.

## 0.1.57
* `RestApiUserSystemSettingsResponse.missedCallsCount` hinzufügen

## 0.1.56
* CI Update

## 0.1.54
* `RestApiDOCUframeManager.postExecuteInterfaceMacro` body optional machen

## 0.1.53
* Entfernen von nicht sicheren Funktionen
* Funktion `RestApiDOCUframeManager.postExecuteInterfaceMacro` hinzufügen um Schnitstellenmakros in DOCUframe aufzurufen

## 0.1.52
* `RestApiUserSystemSettingsResponse` Parameter `eventSettings` um die Einstellungen die durch ein Eventmakro gesetzt werden zurückzugeben - Bugfix

## 0.1.51
* `RestApiDOCUframeManager.postMessageSend` Parameter `actions` hinzugefügt um zusätzliche Aktionen auszuführen
* `RestApiDOCUframeManager.postMessage` Parameter `actions` hinzugefügt um zusätzliche Aktionen auszuführen
* `RestApiDOCUframeManager.getUserSystemSettings` Parameter `eventMacroName` hinzufügen um ein extra Eventmakro auszuführen um benutzerdefinierte Einstellungen zurückzugeben
* `RestApiUserSystemSettingsResponse` Parameter `eventSettings` um die Einstellungen die durch ein Eventmakro gesetzt werden zurückzugeben

## 0.1.50
* `RestApiDOCUframeManager.setObjectSecurity` Parameter `replace` hinzugefügt um Rechte für ein Objekt zu ersetzten

## 0.1.49
* `RestApiDOCUframeManager.setObjectSecurity` Funktion um Rechte für ein Objekt zu setzten

## 0.1.48
* `RestApiDOCUframeConfig.useFolderPathEncoding` hinzufügen. Proxy fehler bei normalen \ in Pfaden der URL

## 0.1.47
* `RestApiDOCUframeManager.saveMailAttachmentsToDatabase` Bugfix | Falscher Makroname

## 0.1.46
* `RestApiDOCUframeConfig.useBase64UrlParameter` Bugfix

## 0.1.45
* `RestApiDOCUframeConfig.useBase64UrlParameter` Parameter hinzugefügt um URL-Parameter als einen Base64 String zu schicken. Erst ab GSD-Connect Version 1.0.0.29 verfügbar.

## 0.1.44
* `RestApiDOCUframeManager.saveMailAttachmentsToDatabase` Funktion hinzufügen um Email-Anhänge in die DOCUframe Datenbank zu speichern

## 0.1.43
* Priority-Zone-System implementiert mit RequestPriority enum (high, normal, low)
* executeWithPriority() Funktion für priority-basierte API-Aufrufe hinzugefügt
* Separate Priority-Buffer für jede Prioritätsstufe implementiert
* Zone-basierte Request-Isolation für parallele Priority-Verarbeitung
* Lösung für blockierende Hintergrund-Requests bei gleichzeitigen Vordergrund-Operationen

## 0.1.42
* Multi-Request Bugfix bei fehlgeschlagener Anfrage aufgrund einer ungültigen Session

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
* `RestApiDOCUframeManager.executeWithoutBuffering` Funktion implementiert für direkte API-Aufrufe ohne Buffering

## 0.1.35
* Modulare Architektur mit separaten Konfigurationsobjekten implementiert
* RestApiDOCUframeConfig-Klasse für zentrale Konfigurationsverwaltung hinzugefügt
* RestApiDOCUframeCallbacks-Klasse für typ-sicheres Event-Management implementiert
* RestApiConfig als Basisklasse für grundlegende API-Konfiguration erstellt
* RestApiCallbacks als Basis-Callback-System für grundlegende Events implementiert
* Konstruktor-Parameter auf config- und callbacks-Objekte umgestellt
* Verbesserte Testbarkeit durch isolierte Konfiguration und Event-Logik
* Bessere Wartbarkeit durch getrennte Verantwortlichkeiten
* Sync Abfragen implementiert
* Custom Abfragen implementiert

## 0.1.34
* Web: Hochladen von Dateien bugfix

## 0.1.33
* Getter und Setter für Multi-Request Modus und Buffergröße

## 0.1.32
* Multi-Request-System, mehrere API-Aufrufe  bündeln und in einer einzigen HTTP-Anfrage zu senden.

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
* RestAPIUploadFile einbauen | Refaktor, Entfernen von unnötigen packages
* CI-Update - Automatisches Code Fix, formatieren und analysieren

## 0.1.26
* MDM 2.0 Version unterstützen | Bugfix

## 0.1.25
* Lint fehler beheben
* MDM 2.0 Version unterstützen

## 0.1.24
* Parameter hinzufügen, um hochgeladene Dateien zu benennen
* Log Callback hinzufügen

## 0.1.23
* Zwei Faktor Authentifizierung: 2FA Parameter in Header und Body übergeben

## 0.1.21
* Zwei Faktor Authentifizierung: Event bei fehlenden 2FA Token auslösen

## 0.1.20
* Aktionen bei der patchMail Funktion mit eingebaut

## 0.1.19
* Demo Link hinzufügen in README.md
* CI-Update - Automatisches Formatieren vom Code bevor es in pub.dev hochgeladen wird.

## 0.1.18
* Zwei Faktor Authentifizierung funktionen hinzufügen
* Unnötige extensions entfernen

## 0.1.17
* CI-Update - überprüfen das die CHANGELOG.md einen Eintrag für die nächste Version enthält.
* CI-Update - Automatisches Formatieren vom Code bevor es in pub.dev hochgeladen wird.

## 0.1.16
* Datei-Upload Bugfix

## 0.1.15
* Beispiel Bugfix
* CI-Update

## 0.1.13
* CI-Update - Beispiel App mit erstellen

## 0.1.12
* Entfernen von nicht benötigten parameter aus `RestApiDOCUframeManager.getUploadFile`

## 0.1.11
* Datei-Upload-Response Bugfix

## 0.1.10
* Asynchroner Datei-Upload-Controller für verbesserte Upload-Verwaltung hinzugefügt
* `RestAPIFileUploadController` Klasse zur Überwachung des Upload-Fortschritts eingeführt
* `RestApiDOCUframeManager.uploadFileWithController()` Methode hinzugefügt um Uploads zu starten und sofort Upload-ID zu erhalten
* Upload-Abbruch-Funktionalität implementiert
* Verbesserte Fehlerbehandlung und Status-Verfolgung für Datei-Uploads
* Umfassende deutsche Dokumentation für Upload-Controller hinzugefügt
* Upload-Methoden refaktoriert mit verbesserter Trennung der Verantwortlichkeiten
* `RestApiDOCUframeManager.getUploadFile()` Methode zum Abrufen von Upload-Metadaten hinzugefügt

## 0.1.9
* Pakete aktualisiert

## 0.1.8
* Lint-Fehler behoben

## 0.1.7
* Abhängigkeiten aktualisiert
* Beispiel-App hinzugefügt
* Pub Points Status verbessert

## 0.1.1
* Erste Veröffentlichung des GSD RestAPI Pakets
* Umfassende REST API Funktionalität für Flutter-Anwendungen
* Automatisches Session-Management mit automatischer Erneuerung
* Unterstützung für alle HTTP-Methoden (GET, POST, PUT, PATCH, DELETE)
* RSA- und AES-Verschlüsselung für sichere Authentifizierung
* Gerätespezifische Authentifizierung und Verwaltung
* Firebase Performance Monitoring Integration
* Konfigurierbare SSL-Zertifikat-Validierung
* Timeout-Konfiguration für Verbindung und Antworten
* E-Mail-Funktionalität (erstellen, bearbeiten, senden)
* Kalender-Verwaltung mit Serien-Unterstützung
* Datei-Upload/Download-Funktionen
* Umfassende Fehlerbehandlung mit spezifischen Exceptions
* Plattformübergreifende Unterstützung (Android, iOS, Web, Windows, macOS, Linux)
* Web-Plattform-Unterstützung mit konditionalen Exporten
* Event-gesteuerte Architektur für Session- und Authentifizierungs-Überwachung
* Professionelle REST API Kommunikation mit sauberer Architektur