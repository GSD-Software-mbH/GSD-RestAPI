# GSD-RestAPI

Dieses Paket bietet umfassende REST-API-Funktionen für Flutter-Anwendungen mit automatischer Session-Verwaltung, Verschlüsselung, verschiedenen HTTP-Methoden und konfigurierbarem Performance-Monitoring.

**👉 [Online-Demo ansehen](https://docs.gsd-software.com/Help/WebApp/flutterSDKdemo/gsd_restapi/index.html)**

## Features

- **Vollständige HTTP-Unterstützung**: GET, POST, PUT, PATCH, DELETE Methoden
- **Automatische Session-Verwaltung**: Sessions werden automatisch erneuert bei Ablauf
- **Sichere Authentifizierung**: Login mit MD5-Hash und RSA/AES-Verschlüsselung
- **Device-Management**: Geräte-spezifische Authentifizierung und Verwaltung
- **Performance-Monitoring**: Konfigurierbares HTTP-Metriken-System via Callbacks
- **SSL-Fehlerbehandlung**: Konfigurierbare SSL-Zertifikatsprüfung
- **Timeout-Konfiguration**: Separate Timeouts für Verbindung und Response
- **Mail-Funktionen**: E-Mail erstellen, bearbeiten und versenden
- **Termin-Management**: Kalender-Funktionen mit Serien-Unterstützung
- **Datei-Upload/Download**: Umfassende Datei-Operationen
- **Error-Handling**: Spezifische Exceptions für verschiedene Fehlertypen
- **Callback-System**: Ereignisbasierte Behandlung für Session-, Lizenz- und Authentifizierungsereignisse
- **Web-Kompatibilität**: Funktioniert sowohl auf mobilen Plattformen als auch im Web

## Installation

Fügen Sie das Paket in Ihrer `pubspec.yaml` hinzu:

```yaml
dependencies:
  gsd_restapi: [version]
```

Führen Sie anschließend `flutter pub get` aus, um das Paket zu installieren.

## Nutzung

### RestAPI Manager initialisieren

Erstellen Sie eine Instanz des RestApiManagers mit den erforderlichen Parametern:

```dart
import 'package:gsd_restapi/gsd_restapi.dart';

final RestApiDOCUframeManager apiManager = RestApiDOCUframeManager(
  'GSD-DFApp',                    // App Key
  'GSDAdmin',                     // Username
  ['GSD-RestApi', 'GSD-DFApp'],  // App Names
  'https://127.0.0.1:8080',      // Server URL
  'dfapp',                       // Database Alias
  perPageCount: 50,
  allowSslError: false,
);
```

### Benutzer anmelden

```dart
try {
  // Passwort als MD5-Hash setzen
  apiManager.setPassword('098f6bcd4621d373cade4e832627b4f6'); // MD5 für "test"
  
  // Login durchführen
  RestApiLoginResponse loginResponse = await apiManager.login(
    '098f6bcd4621d373cade4e832627b4f6'
  );
  
  if (loginResponse.isOk) {
    print('Erfolgreich angemeldet. Session ID: ${apiManager.sessionId}');
  }
} catch (e) {
  print('Login fehlgeschlagen: $e');
}
```

### Session-Überwachung

```dart
// Session-Status prüfen
try {
  RestApiResponse sessionCheck = await apiManager.checkSession();
  print('Session ist aktiv: ${sessionCheck.isOk}');
} catch (e) {
  print('Session ungültig: $e');
}

// Service-Status prüfen
RestApiCheckServiceResponse serviceCheck = await apiManager.checkService();
print('Service verfügbar: ${serviceCheck.isOk}');
```

### Callback-Konfiguration

```dart
// Session-Änderungen überwachen
apiManager.onSessionIdChanged = (String sessionId) async {
  if (sessionId.isEmpty) {
    print('Benutzer wurde abgemeldet');
  } else {
    print('Neue Session ID: $sessionId');
  }
};

// Authentifizierungsfehler überwachen
apiManager.onUserAndPassWrong = (UserAndPassWrongException e) async {
  print('Anmeldung fehlgeschlagen: ${e.message}');
};

// Lizenzfehler überwachen
apiManager.onLicenseWrong = (LicenseException e) async {
  print('Lizenzproblem erkannt: ${e.message}');
};

// HTTP-Metriken für Performance-Monitoring
apiManager.onHttpMetricRecorded = (RestApiHttpMetric metric) async {
  print('API Call: ${metric.method} ${metric.path}');
  print('Duration: ${metric.duration?.inMilliseconds}ms');
  print('Response: ${metric.responseCode} (${metric.responsePayloadSize} bytes)');
};

// 2FA-Token Callback für Session-Erneuerung
apiManager.onMissing2FAToken = () async {
  // Hier sollte ein Dialog zur 2FA-Eingabe gezeigt werden
  String? token = await showTwoFactorDialog();
  return token ?? "";
};

// Log-Nachrichten empfangen
apiManager.onLogMessage = (String message) async {
  print("RestAPI Log: $message");
};
```

## HTTP-Methoden

Das Paket unterstützt alle gängigen HTTP-Methoden:

- **GET**: Daten abrufen
- **POST**: Neue Daten erstellen
- **PUT**: Daten vollständig ersetzen
- **PATCH**: Daten teilweise aktualisieren
- **DELETE**: Daten löschen

## Sicherheit und Verschlüsselung

- **RSA-Verschlüsselung**: Sichere Übertragung von Login-Daten
- **AES-Verschlüsselung**: Verschlüsselte Kommunikation für sensible Daten
- **Session-Management**: Automatische Erneuerung abgelaufener Sessions
- **SSL-Unterstützung**: Konfigurierbare SSL-Zertifikatsprüfung
- **MD5-Hash**: Passwort-Hashing für sichere Authentifizierung

## Error-Handling

Das Paket bietet spezifische Exception-Typen:

- `SessionInvalidException`: Session ist ungültig oder abgelaufen
- `TokenOrSessionIsMissingException`: Token oder Session fehlt
- `UserAndPassWrongException`: Falsche Anmeldedaten
- `LicenseException`: Lizenzprobleme
- `HttpRequestException`: HTTP-spezifische Fehler
- `SecurityException`: Sicherheitsprobleme
- `WebServiceException`: Webservice-Fehler

## Performance-Monitoring

Das Paket bietet ein flexibles Metriken-System zur Überwachung der API-Performance:

```dart
// HTTP-Metriken-Callback konfigurieren
apiManager.onHttpMetricRecorded = (RestApiHttpMetric metric) async {
  // Performance-Daten analysieren
  print('API Request: ${metric.method} ${metric.path}');
  print('Response Code: ${metric.responseCode}');
  print('Duration: ${metric.duration?.inMilliseconds}ms');
  print('Response Size: ${metric.responsePayloadSize} bytes');
  print('Content Type: ${metric.responseContentType}');
  
  // An externes Monitoring-System senden (z.B. Firebase, Sentry, etc.)
  await sendToMonitoringService(metric.toMap());
};
```

### Verfügbare Metriken

- **HTTP-Methode**: GET, POST, PUT, PATCH, DELETE
- **Request-Pfad**: API-Endpunkt-URL
- **Response-Code**: HTTP-Status-Code
- **Request-Dauer**: Zeitspanne der Anfrage in Millisekunden
- **Payload-Größen**: Request- und Response-Größe in Bytes
- **Content-Type**: MIME-Type der Antwort
- **Zeitstempel**: Start- und End-Zeit der Anfrage

## Konfiguration

### Timeout-Einstellungen

```dart
// Timeouts werden intern verwaltet:
// - Connection Timeout: 5 Sekunden
// - Response Timeout: 10 Minuten
```

### SSL-Konfiguration

```dart
RestApiDOCUframeManager apiManager = RestApiDOCUframeManager(
  // ... andere Parameter
  allowSslError: true,  // SSL-Fehler ignorieren
);
```

## API-Design

Das Paket folgt dem Prinzip der **sauberen Architektur**:

- ✅ `RestApiManager` - Hauptklasse für alle API-Operationen
- ✅ `RestApiResponse` - Standardisierte Response-Behandlung
- ✅ `RestApiDevice` - Geräte-Management
- ✅ `HttpMethod` - Enum für HTTP-Methoden
- ❌ `_http()` - Private HTTP-Implementierung (nicht zugänglich)
- ❌ `_performRequest()` - Interne Request-Verarbeitung (nicht zugänglich)

## Callback-Funktionen

Das Paket bietet verschiedene Callback-Funktionen für ereignisbasierte Behandlung:

### Session-Management
- `onSessionIdChangedEvent`: Wird bei Session-Änderungen aufgerufen
- `onMissing2FAToken`: Für 2FA-Token-Eingabe bei Session-Erneuerung

### Fehlerbehandlung
- `onUserAndPassWrong`: Bei Authentifizierungsfehlern
- `onLicenseWrong`: Bei Lizenzproblemen

### Monitoring & Logging
- `onHttpMetricRecorded`: Für Performance-Metriken aller HTTP-Requests
- `onLogMessage`: Für Debug- und Log-Nachrichten

## Hinweise

- **Automatische Session-Erneuerung**: Abgelaufene Sessions werden automatisch erneuert
- **Performance-Monitoring**: HTTP-Requests werden über Callback-System überwacht
- **Web-Unterstützung**: Plattformspezifische HTTP-Client-Implementierung
- **Concurrent Requests**: Schutz vor doppelten Login-Requests
- **Request Caching**: Pending Requests werden gecacht um Duplikate zu vermeiden
- **Memory Management**: HTTP-Clients werden automatisch geschlossen
- **Callback-basiert**: Flexible ereignisbasierte Architektur ohne externe Abhängigkeiten

Dieses Paket ermöglicht die professionelle REST-API-Kommunikation in Ihrer Flutter-Anwendung und bietet umfassende Funktionen für Authentifizierung, Datenmanagement und Performance-Überwachung bei gleichzeitig sauberer und sicherer API.
