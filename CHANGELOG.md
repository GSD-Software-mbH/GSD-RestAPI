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

* Entfernen von nicht benötigten parameter aus `getUploadFile`

## 0.1.11

* Datei-Upload-Response Bugfix

## 0.1.10

* Asynchroner Datei-Upload-Controller für verbesserte Upload-Verwaltung hinzugefügt
* `RestAPIFileUploadController` Klasse zur Überwachung des Upload-Fortschritts eingeführt
* `uploadFileWithController()` Methode hinzugefügt um Uploads zu starten und sofort Upload-ID zu erhalten
* Upload-Abbruch-Funktionalität implementiert
* Verbesserte Fehlerbehandlung und Status-Verfolgung für Datei-Uploads
* Umfassende deutsche Dokumentation für Upload-Controller hinzugefügt
* Upload-Methoden refaktoriert mit verbesserter Trennung der Verantwortlichkeiten
* `getUploadFile()` Methode zum Abrufen von Upload-Metadaten hinzugefügt

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