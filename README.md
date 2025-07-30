# Flutter RestAPI

Dieses Paket bietet umfassende REST-API-Funktionen für Flutter-Anwendungen mit automatischer Session-Verwaltung, Verschlüsselung, verschiedenen HTTP-Methoden und Firebase Performance Monitoring. Es ermöglicht die strukturierte Kommunikation mit REST-APIs sowohl für Debug-Zwecke als auch für die Produktionsüberwachung.

## Features

- **Vollständige HTTP-Unterstützung**: GET, POST, PUT, PATCH, DELETE Methoden
- **Automatische Session-Verwaltung**: Sessions werden automatisch erneuert bei Ablauf
- **Sichere Authentifizierung**: Login mit MD5-Hash und RSA/AES-Verschlüsselung
- **Device-Management**: Geräte-spezifische Authentifizierung und Verwaltung
- **Firebase Performance Monitoring**: Integrierte Performance-Überwachung
- **SSL-Fehlerbehandlung**: Konfigurierbare SSL-Zertifikatsprüfung
- **Timeout-Konfiguration**: Separate Timeouts für Verbindung und Response
- **Mail-Funktionen**: E-Mail erstellen, bearbeiten und versenden
- **Termin-Management**: Kalender-Funktionen mit Serien-Unterstützung
- **Datei-Upload/Download**: Umfassende Datei-Operationen
- **Error-Handling**: Spezifische Exceptions für verschiedene Fehlertypen
- **Web-Kompatibilität**: Funktioniert sowohl auf mobilen Plattformen als auch im Web

## Installation

Fügen Sie das Paket in Ihrer `pubspec.yaml` hinzu:

```yaml
dependencies:
  restapi:
    git:
      url: [Ihre Repository URL]
      ref: main
```

Führen Sie anschließend `flutter pub get` aus, um das Paket zu installieren.

## Nutzung

### RestAPI Manager initialisieren

Erstellen Sie eine Instanz des RestApiManagers mit den erforderlichen Parametern:

```dart
import 'package:restapi/restapimanager.dart';

final RestApiManager apiManager = RestApiManager(
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

### Event-Handling

```dart
// Session-Änderungen überwachen
apiManager.sessionIdChangedEvent.subscribe((args) {
  print('Session ID hat sich geändert');
});

// Authentifizierungsfehler überwachen
apiManager.userAndPassWrongEvent.subscribe((args) {
  print('Benutzername oder Passwort falsch');
});

// Lizenzfehler überwachen
apiManager.licenseWrongEvent.subscribe((args) {
  print('Lizenzproblem erkannt');
});
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

```dart
import 'package:firebase_performance/firebase_performance.dart';

// Firebase Performance Monitoring aktivieren
FirebasePerformance performance = FirebasePerformance.instance;

RestApiManager apiManager = RestApiManager(
  // ... andere Parameter
  firebasePerformance: performance,
);
```

## Konfiguration

### Timeout-Einstellungen

```dart
// Timeouts werden intern verwaltet:
// - Connection Timeout: 5 Sekunden
// - Response Timeout: 10 Minuten
```

### SSL-Konfiguration

```dart
RestApiManager apiManager = RestApiManager(
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

## Hinweise

- **Automatische Session-Erneuerung**: Abgelaufene Sessions werden automatisch erneuert
- **Performance**: Requests werden mit Firebase Performance Monitoring überwacht
- **Web-Unterstützung**: Plattformspezifische HTTP-Client-Implementierung
- **Concurrent Requests**: Schutz vor doppelten Login-Requests
- **Request Caching**: Pending Requests werden gecacht um Duplikate zu vermeiden
- **Memory Management**: HTTP-Clients werden automatisch geschlossen

Dieses Paket ermöglicht die professionelle REST-API-Kommunikation in Ihrer Flutter-Anwendung und bietet umfassende Funktionen für Authentifizierung, Datenmanagement und Performance-Überwachung bei gleichzeitig sauberer und sicherer API.
