part of '../gsd_restapi.dart';

/// Basis-Konfigurationsklasse für REST-API-Parameter
///
/// Diese Basisklasse kapselt grundlegende Konfigurationseinstellungen für REST-API-Manager:
/// - Server-Verbindungsparameter (URL, SSL-Einstellungen)
/// - Timeout-Konfigurationen für HTTP-Verbindungen
/// - Datenbank-Alias für Multi-Datenbank-Umgebungen
/// - SSL-Sicherheitseinstellungen
///
/// Die Klasse dient als Basis für spezialisierte Konfigurationen wie RestApiDOCUframeConfig
/// und bietet grundlegende Validierung und Initialisierung.
///
/// Vorteile:
/// - Zentrale Verwaltung grundlegender Konfigurationswerte
/// - Typ-sichere Basis-Konfiguration
/// - Einfache Validierung und Default-Werte
/// - Bessere Testbarkeit durch isolierte Konfiguration
/// - Erweiterbar für spezielle Anwendungsfälle
class RestApiConfig {
  /// Datenbank-Alias für Multi-Datenbank-Umgebungen
  /// Beispiel: `dfapp`
  final String alias;

  /// Server-URL mit Protokoll, IP und Port
  /// Beispiel: `https://127.0.0.1:8080`
  final String serverUrl;

  /// Erlaubt SSL-Zertifikatsfehler (nur für Development)
  bool allowSslError;

  /// Timeout für HTTP-Verbindungsaufbau (5 Sekunden)
  final Duration connectionTimeout = const Duration(seconds: 5);

  /// Timeout für HTTP-Antworten (10 Minuten)
  final Duration responseTimeout = const Duration(minutes: 10);

  /// Basis-URI für alle API-Aufrufe
  late Uri _baseUri;

  /// Konstruktor für RestApiConfig
  ///
  /// [serverUrl] - Server-URL mit Protokoll, IP und Port (erforderlich)
  /// [alias] - Datenbank-Alias für Multi-Datenbank-Umgebungen (erforderlich)
  /// [allowSslError] - SSL-Fehler erlauben (Standard: false)
  RestApiConfig({
    required this.serverUrl,
    required this.alias,
    this.allowSslError = false,
  }) {
    _validateAndInitialize();
  }

  /// Validiert die Konfiguration und initialisiert interne Werte
  void _validateAndInitialize() {
    // Server-URL validieren
    if (serverUrl.isNotEmpty) {
      try {
        _baseUri = Uri.parse(serverUrl);
        if (!_baseUri.hasScheme || !_baseUri.hasAuthority) {
          throw FormatException('Ungültige Server-URL: $serverUrl');
        }
      } catch (e) {
        throw ArgumentError('Ungültige Server-URL: $serverUrl - $e');
      }
    }
  }

  /// Setzt SSL-Fehler-Toleranz
  void setAllowSslError(bool allowSslError) {
    this.allowSslError = allowSslError;
  }

  /// String-Repräsentation der Konfiguration
  @override
  String toString() {
    return 'RestApiConfig(serverUrl: $serverUrl, alias: $alias, allowSslError: $allowSslError)';
  }
}
