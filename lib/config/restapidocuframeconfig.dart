part of '../gsd_restapi.dart';

/// Erweiterte Konfigurationsklasse für DOCUframe REST-API-Parameter
///
/// Diese Klasse erweitert RestApiConfig und kapselt alle DOCUframe-spezifischen
/// Konfigurationseinstellungen für den RestApiDOCUframeManager:
/// - Authentifizierungseinstellungen (App-Key, Benutzername, Anwendungsnamen)
/// - Buffer-Einstellungen für Multi-Requests und Batch-Verarbeitung
/// - Session-Management und Login-Konfigurationen (v2-Login, 2FA)
/// - Paginierungs- und Performance-Einstellungen
/// - Zusätzlich zu den Basis-Einstellungen (Server, SSL, Timeouts)
///
/// Die Klasse erweitert die Basis-Funktionalität um DOCUframe-spezifische
/// Konfigurationsmöglichkeiten und bietet vollständige API-Konfiguration.
///
/// Vorteile:
/// - Zentrale Verwaltung aller DOCUframe-Konfigurationswerte
/// - Typ-sichere erweiterte Konfiguration
/// - Einfache Validierung und Default-Werte
/// - Bessere Testbarkeit durch isolierte Konfiguration
/// - Dynamische Konfigurationsänderungen zur Laufzeit
class RestApiDOCUframeConfig extends RestApiConfig {
  int get perPageCount => _perPageCount;
  int get maxBufferSize => _maxBufferSize;
  int get bufferFlushDelayMs => _bufferFlushDelayMs;

  /// App-Schlüssel für die API-Authentifizierung
  /// Beispiel: `GSD-DFApp`
  final String appKey;

  /// Benutzername für die Anmeldung
  /// Beispiel: `GSDAdmin`
  final String userName;

  /// Liste der Anwendungsnamen
  /// Beispiel: `['GSD-RestApi', 'GSD-DFApp']`
  List<String> appNames;

  /// Zusätzliche Anwendungsnamen (können dynamisch hinzugefügt werden)
  List<String> additionalAppNames = [];

  /// Optionales Gerät für die Anmeldung (Push-Benachrichtigungen)
  RestApiDevice? device;

  /// Anzahl der Elemente pro Seite bei paginierten Anfragen
  int _perPageCount;

  /// Aktiviert Multi-Request-Modus für Batch-Verarbeitung ab GSD-Connect Version 1.0.0.30
  bool multiRequest;

  /// Verwendet Base64-kodierte URL-Parameter für Anfragen ab GSD-Connect Version 1.0.0.29
  bool useBase64UrlParameter;

  /// Verwendet Ordnerpfad-Codierung für Pfad-Parameter in API-Aufrufen
  bool useFolderPathEncoding;

  /// Maximale Buffer-Größe vor automatischem Flush
  int _maxBufferSize;

  /// Maximale Wartezeit in Millisekunden vor Flush
  int _bufferFlushDelayMs;

  /// Aktuelle Session-ID (wird vom Auth-System verwaltet)
  String sessionId = "";

  /// Konstruktor für RestApiConfig
  ///
  /// [appKey] - App-Schlüssel für die API-Authentifizierung (erforderlich)
  /// [userName] - Benutzername für die Anmeldung (erforderlich)
  /// [appNames] - Liste der Anwendungsnamen (erforderlich)
  /// [serverUrl] - Server-URL mit Protokoll, IP und Port (erforderlich)
  /// [alias] - Datenbank-Alias für Multi-Datenbank-Umgebungen (erforderlich)
  /// [device] - Optionales Gerät für die Anmeldung
  /// [perPageCount] - Anzahl der Elemente pro Seite (Standard: 50)
  /// [bufferFlushDelayMs] - Buffer-Flush-Delay in Millisekunden (Standard: 100)
  /// [maxBufferSize] - Maximale Buffer-Größe (Standard: 10)
  /// [useBase64UrlParameter] - Base64-kodierte URL-Parameter verwenden (Standard: false) ab GSD-Connect Version 1.0.0.29
  /// [useFolderPathEncoding] - Ordnerpfad-Codierung verwenden (Standard: false) ab GSD-Connect Version 1.0.0.29
  /// [allowSslError] - SSL-Fehler erlauben (Standard: false)
  /// [multiRequest] - Multi-Request-Modus aktivieren (Standard: false) ab GSD-Connect Version 1.0.0.30
  RestApiDOCUframeConfig({
    required this.appKey,
    required this.userName,
    required this.appNames,
    required super.serverUrl,
    required super.alias,
    this.device,
    int perPageCount = 50,
    int bufferFlushDelayMs = 100,
    int maxBufferSize = 10,
    this.useBase64UrlParameter = false,
    this.useFolderPathEncoding = false,
    super.allowSslError = false,
    this.multiRequest = false,
    this.sessionId = "",
  }) : _perPageCount = perPageCount,
       _bufferFlushDelayMs = bufferFlushDelayMs,
       _maxBufferSize = maxBufferSize {
    _validateAndInitialize();
  }

  /// Validiert die Konfiguration und initialisiert interne Werte
  @override
  void _validateAndInitialize() {
    super._validateAndInitialize();

    // Numerische Werte validieren
    if (_perPageCount <= 0) {
      throw ArgumentError('perPageCount muss größer als 0 sein');
    }

    if (_maxBufferSize <= 0) {
      throw ArgumentError('maxBufferSize muss größer als 0 sein');
    }

    if (_bufferFlushDelayMs < 0) {
      throw ArgumentError('bufferFlushDelayMs darf nicht negativ sein');
    }
  }

  /// Erstellt eine URI für API-Aufrufe
  ///
  /// [path] - Der API-Endpunkt-Pfad
  /// [params] - Optionale Query-Parameter
  ///
  /// Returns: Vollständige URI für den API-Aufruf
  Uri getUri(String path, {Map<String, String>? params}) {
    String pathCombined = "${_baseUri.path}$path";

    return Uri(
      scheme: _baseUri.scheme,
      host: _baseUri.host,
      port: _baseUri.port,
      path: pathCombined,
      queryParameters: params,
    );
  }

  /// Erstellt HTTP-Header für API-Anfragen
  ///
  /// [contentType] - MIME-Type des Request-Bodies
  /// [addAppKey] - App-Schlüssel zu Headern hinzufügen
  /// [addSessionId] - Session-ID zu Headern hinzufügen
  ///
  /// Returns: Map mit HTTP-Headern
  Map<String, String> getHeaders({
    String contentType = "application/json; charset=utf-8",
    bool addAppKey = true,
    bool addSessionId = true,
  }) {
    Map<String, String> headers = {};

    if (contentType.isNotEmpty) {
      headers['Content-type'] = contentType;
    }

    if (addAppKey) {
      headers['appkey'] = appKey;
    }

    if (addSessionId && sessionId.isNotEmpty) {
      headers['sessionid'] = sessionId;
    }

    return headers;
  }

  /// Gibt die vollständige Liste aller App-Namen zurück
  List<String> getAllAppNames() {
    List<String> allNames = [];
    allNames.addAll(appNames);
    allNames.addAll(additionalAppNames);
    return allNames;
  }

  /// **Setter-Methoden für dynamische Konfigurationsänderungen**

  /// Setzt maximale Buffer-Größe
  void setMaxBufferSize(int maxBufferSize) {
    if (maxBufferSize <= 0) {
      throw ArgumentError('maxBufferSize muss größer als 0 sein');
    }
    _maxBufferSize = maxBufferSize;
  }

  /// Setzt Buffer-Flush-Delay
  void setBufferFlushDelayMs(int bufferFlushDelayMs) {
    if (bufferFlushDelayMs < 0) {
      throw ArgumentError('bufferFlushDelayMs darf nicht negativ sein');
    }
    _bufferFlushDelayMs = bufferFlushDelayMs;
  }

  /// Setzt per-Page-Count für Paginierung
  void setPerPageCount(int perPageCount) {
    if (perPageCount <= 0) {
      throw ArgumentError('perPageCount muss größer als 0 sein');
    }
    _perPageCount = perPageCount;
  }

  /// String-Repräsentation der Konfiguration
  @override
  String toString() {
    return 'RestApiConfig(appKey: $appKey, userName: $userName, serverUrl: $serverUrl, alias: $alias)';
  }
}
