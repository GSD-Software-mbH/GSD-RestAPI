import 'package:gsd_restapi/src/client/gsd_api_client.dart';
import 'package:gsd_restapi/src/models/gsd_docuframe_device.dart';

/// Konfiguration eines [GsdApiClient].
///
/// Kapselt alle Einstellungen für `GsdApiClient`:
/// - Server-Verbindungsparameter (URL, Alias, SSL-Einstellungen, Timeouts)
/// - Authentifizierungseinstellungen (App-Key, Benutzername, Anwendungsnamen)
/// - Buffer-Einstellungen für Multi-Requests und Batch-Verarbeitung
/// - Session-Management und Login-Konfigurationen (v2-Login, 2FA)
/// - Paginierungs- und Performance-Einstellungen
///
/// Vorteile:
/// - Zentrale Verwaltung aller DOCUframe-Konfigurationswerte
/// - Typ-sichere erweiterte Konfiguration
/// - Einfache Validierung und Default-Werte
/// - Bessere Testbarkeit durch isolierte Konfiguration
///
/// Die Konfiguration ist unveränderlich. Eine gespeicherte Session übergibt
/// `GsdApiClient(sessionId: ...)`; die zur Laufzeit erlaubten Änderungen laufen
/// über `GsdApiClient.updateRuntimeSettings()` und `GsdApiClient.setDevice()`.
class GsdApiConfig {
  /// Konstruktor für GsdApiConfig
  ///
  /// [appKey] - App-Schlüssel für die API-Authentifizierung (erforderlich)
  /// [userName] - Benutzername für die Anmeldung (erforderlich)
  /// [appNames] - Liste der Anwendungsnamen (erforderlich)
  /// [additionalAppNames] - Zusätzliche Anwendungsnamen (Standard: leer)
  /// [serverUrl] - Server-URL mit Protokoll, IP und Port (erforderlich)
  /// [alias] - Datenbank-Alias für Multi-Datenbank-Umgebungen (erforderlich)
  /// [device] - Optionales Gerät für die Anmeldung
  /// [perPageCount] - Anzahl der Elemente pro Seite (Standard: 50)
  /// [bufferFlushDelayMs] - Buffer-Flush-Delay in Millisekunden (Standard: 100)
  /// [maxBufferSize] - Maximale Buffer-Größe (Standard: 10)
  /// [useBase64UrlParameter] - Base64-kodierte URL-Parameter verwenden
  ///   (Standard: false) ab GSD-Connect Version 1.0.0.29
  /// [useFolderPathEncoding] - Ordnerpfad-Codierung verwenden
  ///   (Standard: false) ab GSD-Connect Version 1.0.0.29
  /// [allowSslError] - SSL-Fehler erlauben (Standard: false)
  /// [multiRequest] - Multi-Request-Modus aktivieren (Standard: false)
  ///   ab GSD-Connect Version 1.0.0.30
  GsdApiConfig({
    required this.appKey,
    required this.userName,
    required this.appNames,
    required this.serverUrl,
    required this.alias,
    this.additionalAppNames = const [],
    this.device,
    this.perPageCount = 50,
    this.bufferFlushDelayMs = 100,
    this.maxBufferSize = 10,
    this.useBase64UrlParameter = false,
    this.useFolderPathEncoding = false,
    this.allowSslError = false,
    this.multiRequest = false,
  }) {
    _validate();
  }

  /// Datenbank-Alias für Multi-Datenbank-Umgebungen
  /// Beispiel: `dfapp`
  final String alias;

  /// Server-URL mit Protokoll, IP und Port
  /// Beispiel: `https://127.0.0.1:8080`
  final String serverUrl;

  /// Erlaubt SSL-Zertifikatsfehler (nur für Development)
  final bool allowSslError;

  /// Timeout für HTTP-Verbindungsaufbau (5 Sekunden)
  final Duration connectionTimeout = const Duration(seconds: 5);

  /// Timeout für HTTP-Antworten (10 Minuten)
  final Duration responseTimeout = const Duration(minutes: 10);

  /// App-Schlüssel für die API-Authentifizierung
  /// Beispiel: `GSD-DFApp`
  final String appKey;

  /// Benutzername für die Anmeldung
  /// Beispiel: `admin`
  final String userName;

  /// Liste der Anwendungsnamen
  /// Beispiel: `['GSD-RestApi', 'GSD-DFApp']`
  final List<String> appNames;

  /// Zusätzliche Anwendungsnamen
  final List<String> additionalAppNames;

  /// Optionales Gerät für die Anmeldung (Push-Benachrichtigungen)
  final GsdDocuframeDevice? device;

  /// Anzahl der Elemente pro Seite bei paginierten Anfragen
  final int perPageCount;

  /// Aktiviert Multi-Request-Modus für Batch-Verarbeitung ab GSD-Connect
  /// Version 1.0.0.30
  final bool multiRequest;

  /// Verwendet Base64-kodierte URL-Parameter für Anfragen ab GSD-Connect
  /// Version 1.0.0.29
  final bool useBase64UrlParameter;

  /// Verwendet Ordnerpfad-Codierung für Pfad-Parameter in API-Aufrufen
  final bool useFolderPathEncoding;

  /// Maximale Buffer-Größe vor automatischem Flush
  final int maxBufferSize;

  /// Maximale Wartezeit in Millisekunden vor Flush
  final int bufferFlushDelayMs;

  /// Validiert die Konfiguration.
  void _validate() {
    // Server-URL validieren
    if (serverUrl.isNotEmpty) {
      try {
        final baseUri = Uri.parse(serverUrl);
        if (!baseUri.hasScheme || !baseUri.hasAuthority) {
          throw FormatException('Ungültige Server-URL: $serverUrl');
        }
      } catch (e) {
        throw ArgumentError('Ungültige Server-URL: $serverUrl - $e');
      }
    }

    // Numerische Werte validieren
    if (perPageCount <= 0) {
      throw ArgumentError('perPageCount muss größer als 0 sein');
    }

    if (maxBufferSize <= 0) {
      throw ArgumentError('maxBufferSize muss größer als 0 sein');
    }

    if (bufferFlushDelayMs < 0) {
      throw ArgumentError('bufferFlushDelayMs darf nicht negativ sein');
    }
  }

  /// String-Repräsentation der Konfiguration
  @override
  String toString() {
    return 'GsdApiConfig(appKey: $appKey, userName: $userName, '
        'serverUrl: $serverUrl, alias: $alias, allowSslError: $allowSslError)';
  }
}
