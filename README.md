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
- **Multi-Request-Unterstützung**: Intelligente Bündelung mehrerer API-Aufrufe für bessere Performance
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

**NEUE MODULARE ARCHITEKTUR**: Der RestApiDOCUframeManager verwendet jetzt eine modulare Architektur mit separaten Konfigurationsobjekten und einem Callback-System für bessere Testbarkeit und Wartbarkeit.

Erstellen Sie zunächst eine Konfiguration und optional ein Callback-System:

```dart
import 'package:gsd_restapi/gsd_restapi.dart';

// Konfiguration erstellen
final config = RestApiDOCUframeConfig(
  appKey: 'GSD-DFApp',                    // App Key
  userName: 'GSDAdmin',                   // Username
  appNames: ['GSD-RestApi', 'GSD-DFApp'], // App Names
  serverUrl: 'https://127.0.0.1:8080',   // Server URL
  alias: 'dfapp',                        // Database Alias
  perPageCount: 50,
  allowSslError: false,
  multiRequest: true,                     // Multi-Request aktivieren
);

// Callback-System erstellen (optional)
final callbacks = RestApiDOCUframeCallbacks(
  onLogMessage: (String message) async {
    print("RestAPI Log: $message");
  },
  onHttpMetricRecorded: (RestApiHttpMetric metric) async {
    print("API Call: ${metric.function} - ${metric.duration}ms");
  },
);

// Manager mit Konfiguration und Callbacks initialisieren
final RestApiDOCUframeManager apiManager = RestApiDOCUframeManager(
  config: config,
  callbacks: callbacks,
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
// Callback-System erstellen
final callbacks = RestApiDOCUframeCallbacks(
  // Session-Änderungen überwachen
  onSessionIdChanged: (String sessionId) async {
    if (sessionId.isEmpty) {
      print('Benutzer wurde abgemeldet');
    } else {
      print('Neue Session ID: $sessionId');
    }
  },

  // Authentifizierungsfehler überwachen
  onUserAndPassWrong: (UserAndPassWrongException e) async {
    print('Anmeldung fehlgeschlagen: ${e.message}');
  },

  // Lizenzfehler überwachen
  onLicenseWrong: (LicenseException e) async {
    print('Lizenzproblem erkannt: ${e.message}');
  },

  // 2FA-Token Callback für Session-Erneuerung
  onMissing2FAToken: () async {
    // Hier sollte ein Dialog zur 2FA-Eingabe gezeigt werden
    String? token = await showTwoFactorDialog();
    return token ?? "";
  },

  // HTTP-Metriken für Performance-Monitoring
  onHttpMetricRecorded: (RestApiHttpMetric metric) async {
    print('API Call: ${metric.function} - ${metric.duration}ms');
    print('Response: ${metric.responseCode} (${metric.responsePayloadSize} bytes)');
  },

  // Log-Nachrichten empfangen
  onLogMessage: (String message) async {
    print("RestAPI Log: $message");
  },
);

// Callbacks nachträglich ändern (optional)
callbacks.onSessionIdChanged = (String sessionId) async {
  // Neue Implementierung
};

// Alle Callbacks entfernen
callbacks.clearAllCallbacks();
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
### HTTP-Metriken-Callback konfigurieren
```dart
// Über das Callback-System konfigurieren
final callbacks = RestApiDOCUframeCallbacks(
  onHttpMetricRecorded: (RestApiHttpMetric metric) async {
    // Performance-Daten analysieren
    print('API Request: ${metric.function}');
    print('Duration: ${metric.duration?.inMilliseconds}ms');
    
    // An externes Monitoring-System senden (z.B. Firebase, Sentry, etc.)
    await sendToMonitoringService(metric);
  },
);

// Manager mit Callbacks initialisieren
final apiManager = RestApiDOCUframeManager(
  config: config,
  callbacks: callbacks,
);
```
```

### Verfügbare Metriken

- **HTTP-Methode**: GET, POST, PUT, PATCH, DELETE
- **Request-Pfad**: API-Endpunkt-URL
- **Response-Code**: HTTP-Status-Code
- **Request-Dauer**: Zeitspanne der Anfrage in Millisekunden
- **Payload-Größen**: Request- und Response-Größe in Bytes
- **Content-Type**: MIME-Type der Antwort
- **Zeitstempel**: Start- und End-Zeit der Anfrage

## Multi-Request-System

Das Multi-Request-System ermöglicht es, mehrere API-Aufrufe zu bündeln und in einer einzigen HTTP-Anfrage zu senden. Dies verbessert erheblich die Performance, besonders bei vielen gleichzeitigen API-Aufrufen.

### Aktivierung

```dart
// Multi-Request über Konfiguration aktivieren
final config = RestApiDOCUframeConfig(
  appKey: 'GSD-DFApp',                    // App Key
  userName: 'GSDAdmin',                   // Username
  appNames: ['GSD-RestApi', 'GSD-DFApp'], // App Names
  serverUrl: 'https://127.0.0.1:8080',   // Server URL
  alias: 'dfapp',                        // Database Alias
  multiRequest: true,                     // Multi-Request aktivieren
  maxBufferSize: 10,                     // Maximale Buffer-Größe
  bufferFlushDelayMs: 100,               // Flush-Delay in Millisekunden
);

final RestApiDOCUframeManager apiManager = RestApiDOCUframeManager(
  config: config,
);

// Multi-Request zur Laufzeit ändern
apiManager.config.setMultiRequest(false);  // Deaktivieren
apiManager.config.setMaxBufferSize(15);    // Buffer-Größe ändern
```

### Funktionsweise

**Automatische Pufferung**: API-Aufrufe werden automatisch gepuffert und nach 100ms oder bei 10 Requests gesendet.

**Intelligente Verarbeitung**:
- **Ein Request**: Wird direkt als Einzelanfrage gesendet (optimiert)
- **Mehrere Requests**: Werden als Multi-Request über `/v1/multi` gesendet

**Ausgeschlossene Request-Typen** (werden nie gepuffert):
- Login-Requests (`v2/login`, `v2/login/secure`)
- Logout-Requests (`v1/logout`)  
- Session-Checks (`_CheckSession`)
- Service-Checks (`_CheckService`)

### Beispiel-Verwendung

```dart
// Multi-Request über Konfiguration aktivieren
final config = RestApiDOCUframeConfig(
  // ... andere Parameter
  multiRequest: true,
);

final apiManager = RestApiDOCUframeManager(config: config);

// Mehrere API-Aufrufe - werden automatisch gebündelt
await Future.wait([
  apiManager.getUsers(),
  apiManager.getDocuments(),
  apiManager.getSettings(),
  // Diese 3 Requests werden in einem Multi-Request gesendet
]);
```

### Vorteile

- **Performance**: Reduzierte Netzwerk-Latenz durch weniger HTTP-Verbindungen
- **Effizienz**: Weniger Server-Overhead durch gebündelte Requests
- **Transparenz**: Funktioniert automatisch ohne Code-Änderungen
- **Intelligenz**: Einzelne Requests werden direkt gesendet, keine unnötige Bündelung

### Konfiguration

- **Buffer-Größe**: Maximal 10 Requests pro Multi-Request
- **Flush-Delay**: 100ms Wartezeit vor automatischem Senden
- **Endpoint**: Verwendet `/v1/multi` für gebündelte Requests
- **Kompatibilität**: Erfordert GSD-Connect 1.0.0.30 oder höher

## Priority-System für Multi-Requests

Das Priority-System erweitert das Multi-Request-System um Request-Prioritäten und löst das Problem blockierender Hintergrund-Operationen. Verschiedene Prioritätsstufen ermöglichen eine intelligente Verarbeitung von API-Aufrufen.

### Request-Prioritäten

```dart
enum RequestPriority {
  high,    // Sofortige Verarbeitung, kein Buffering
  normal,  // Standard-Buffering (Default)
  low,     // Erweiterte Pufferung für Hintergrund-Operationen
}
```

### executeWithPriority() Funktion

```dart
// High-Priority für kritische UI-Operationen
RestApiResponse response = await apiManager.executeWithPriority(() async {
  return await apiManager.getFolderByType("Eingang");
}, RequestPriority.high);

// Normal-Priority (Standard-Verhalten)
RestApiResponse normalResponse = await apiManager.executeWithPriority(() async {
  return await apiManager.getUserSettings();
}, RequestPriority.normal);

// Low-Priority für Hintergrund-Loading
List<RestApiResponse> backgroundData = await apiManager.executeWithPriority(() async {
  return [
    await apiManager.getFolderByType("Archiv"),
    await apiManager.getSystemSettings(),
    await apiManager.getDocuments(page: 1),
  ];
}, RequestPriority.low);
```

### Problem-Lösung

**Ursprüngliches Problem:**
- Hintergrund-Loading blockierte Vordergrund-Requests
- Multi-Request-Batches verzögerten interaktive Operationen
- Keine Prioritätsdifferenzierung zwischen kritischen und unkritischen Requests

**Lösung durch Priority-System:**
- **High-Priority** umgeht Multi-Request komplett für sofortige Verarbeitung
- **Separate Priority-Buffer** verhindern gegenseitige Blockierung
- **Zone-basierte Isolation** ermöglicht parallele Verarbeitung verschiedener Prioritäten
- **Backward-Compatibility** - bestehender Code funktioniert unverändert als Normal-Priority

### Verwendungsszenarien

**High-Priority verwenden für:**
- Login/Logout-Operationen
- Kritische UI-Updates
- Benutzer-Interaktionen die sofortige Response benötigen
- Fehlerbehandlung und Session-Erneuerung

**Normal-Priority (Default) für:**
- Standard-CRUD-Operationen
- Reguläre Datenabfragen
- Formulare und Eingaben

**Low-Priority verwenden für:**
- Hintergrund-Synchronisierung
- Prefetching von Daten
- Cache-Aktualisierungen
- Nicht-kritische Datensammlung

### Technische Details

- **Zone-Isolation**: Jede Priority läuft in eigenem Zone-Kontext
- **Separate Timer**: Priority-spezifische Buffer-Flush-Timer
- **Parallele Verarbeitung**: High-Priority kann während Low-Priority Multi-Request laufen
- **Automatischer Fallback**: Bei Multi-Request-Fehlern automatische Einzelrequest-Verarbeitung
- **Performance-Monitoring**: Priority-Information in HTTP-Metriken verfügbar

## Konfiguration

### Timeout-Einstellungen

```dart
// Timeouts werden intern verwaltet:
// - Connection Timeout: 5 Sekunden
// - Response Timeout: 10 Minuten
```

### SSL-Konfiguration

```dart
// SSL-Konfiguration über RestApiDOCUframeConfig
final config = RestApiDOCUframeConfig(
  // ... andere Parameter
  allowSslError: true,  // SSL-Fehler ignorieren
);

final RestApiDOCUframeManager apiManager = RestApiDOCUframeManager(
  config: config,
);

// SSL-Einstellungen zur Laufzeit ändern
apiManager.config.setAllowSslError(false);
```

## API-Design

Das Paket folgt dem Prinzip der **sauberen Architektur** mit **modularem Design**:

### Hauptkomponenten
- ✅ `RestApiDOCUframeManager` - Hauptklasse für alle API-Operationen
- ✅ `RestApiDOCUframeConfig` - Konfigurationsmodul für alle API-Parameter
- ✅ `RestApiDOCUframeCallbacks` - Event-System für Callback-Management
- ✅ `RestApiResponse` - Standardisierte Response-Behandlung
- ✅ `RestApiDevice` - Geräte-Management
- ✅ `HttpMethod` - Enum für HTTP-Methoden

### Basisklassen
- ✅ `RestApiConfig` - Basis-Konfigurationsklasse
- ✅ `RestApiCallbacks` - Basis-Callback-System

### Interne Implementierung (nicht zugänglich)
- ❌ `_http()` - Private HTTP-Implementierung
- ❌ `_performRequest()` - Interne Request-Verarbeitung

### Modulare Architektur
Die neue Architektur trennt Konfiguration, Event-Handling und API-Logik:
- **Konfiguration**: Zentral über `RestApiDOCUframeConfig`
- **Events**: Typ-sicher über `RestApiDOCUframeCallbacks`
- **API-Logik**: Fokussiert in `RestApiDOCUframeManager`

## Callback-System

**MODULARES CALLBACK-SYSTEM**: Das Paket bietet ein zentrales, typ-sicheres Callback-System über die `RestApiDOCUframeCallbacks`-Klasse:

### Architektur
- **RestApiCallbacks** (Basisklasse): Grundlegende Events (Logging, HTTP-Metriken)
- **RestApiDOCUframeCallbacks** (Erweiterte Klasse): DOCUframe-spezifische Events

### Session-Management
- `onSessionIdChanged`: Wird bei Session-Änderungen aufgerufen
- `onMissing2FAToken`: Für 2FA-Token-Eingabe bei Session-Erneuerung

### Fehlerbehandlung
- `onUserAndPassWrong`: Bei Authentifizierungsfehlern
- `onLicenseWrong`: Bei Lizenzproblemen

### Monitoring & Logging
- `onHttpMetricRecorded`: Für Performance-Metriken aller HTTP-Requests
- `onLogMessage`: Für Debug- und Log-Nachrichten

### Callback-Verwaltung
```dart
// Alle Callbacks entfernen
callbacks.clearAllCallbacks();

// Event-Trigger (für interne Verwendung)
await callbacks.triggerSessionIdChangedEvent(sessionId);
await callbacks.triggerLicenseWrongEvent(exception);
```

## Hinweise

- **Automatische Session-Erneuerung**: Abgelaufene Sessions werden automatisch erneuert
- **Performance-Monitoring**: HTTP-Requests werden über Callback-System überwacht
- **Web-Unterstützung**: Plattformspezifische HTTP-Client-Implementierung
- **Concurrent Requests**: Schutz vor doppelten Login-Requests
- **Request Caching**: Pending Requests werden gecacht um Duplikate zu vermeiden
- **Multi-Request-Optimierung**: Intelligente Bündelung für bessere Performance bei mehreren API-Aufrufen
- **Memory Management**: HTTP-Clients werden automatisch geschlossen
- **Modulare Architektur**: Getrennte Konfiguration, Callback-System und API-Logik für bessere Wartbarkeit
- **Typ-sicheres Callback-System**: Zentrale Verwaltung aller Events über RestApiDOCUframeCallbacks
- **Konfigurationsmanagement**: Vollständige Konfiguration über RestApiDOCUframeConfig mit Laufzeit-Änderungen

Dieses Paket ermöglicht die professionelle REST-API-Kommunikation in Ihrer Flutter-Anwendung und bietet umfassende Funktionen für Authentifizierung, Datenmanagement und Performance-Überwachung bei gleichzeitig sauberer und sicherer API.
