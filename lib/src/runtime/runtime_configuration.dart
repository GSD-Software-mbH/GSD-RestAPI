import 'package:meta/meta.dart';

import 'package:gsd_restapi/gsd_restapi.dart';

/// Kontrollierte Momentaufnahme der Verbindungs- und
/// Authentifizierungseinstellungen aus [RestApiDOCUframeConfig].
///
/// Der neue Runtime liest die veränderliche Legacy-Konfiguration nur einmal
/// bei der Erzeugung (`fromDocuframeConfig`) und hält seitdem eine eigene
/// Kopie. Der laufende Sessionzustand lebt danach
/// ausschließlich in `SessionState` - spätere Änderungen an der
/// ursprünglichen [RestApiDOCUframeConfig] (z.B. `sessionId`, `appNames`)
/// wirken sich nicht unkontrolliert auf einen bereits erzeugten Runtime aus.
/// Die wenigen zur Laufzeit unterstützten Werte werden ausschließlich über
/// `DOCUframeApi.management.updateRuntimeSettings()` geändert.
@internal
class RuntimeConfiguration {
  /// Server-URL mit Protokoll, IP und Port, wie in der Konfiguration
  /// hinterlegt (unverändert, ggf. inkl. trailing Slash).
  final String serverUrl;

  /// Aus [serverUrl] geparste Basis-[Uri] für alle API-Aufrufe.
  ///
  /// Der Pfad ist normalisiert: trailing Slashes werden entfernt, damit
  /// beim URI-Aufbau keine doppelten Slashes entstehen
  /// (`https://host:8080/dfapp/` verhält sich wie
  /// `https://host:8080/dfapp`).
  final Uri baseUri;

  /// Datenbank-Alias für Multi-Datenbank-Umgebungen; leer, wenn kein Alias
  /// verwendet wird.
  final String alias;

  /// App-Schlüssel für die API-Authentifizierung.
  final String appKey;

  /// Benutzername für die Anmeldung.
  final String userName;

  /// Defensive Kopie der Anwendungsnamen (ohne [additionalAppNames]).
  List<String> appNames;

  /// Defensive Kopie der zusätzlichen Anwendungsnamen.
  List<String> additionalAppNames;

  /// Optionales Gerät für die Anmeldung (Push-Benachrichtigungen). Wird
  /// vom `SessionCoordinator` für den Login benötigt.
  ///
  /// Hinweis: [RestApiDevice] ist ein veränderlicher Legacy-Typ und wird
  /// hier als REFERENZ übernommen (keine tiefe Kopie) - spätere Mutationen
  /// am Gerät (z.B. neuer Firebase-Token) sind damit bewusst sichtbar.
  RestApiDevice? device;

  /// Timeout für den HTTP-Verbindungsaufbau.
  final Duration connectionTimeout;

  /// Timeout für HTTP-Antworten.
  final Duration responseTimeout;

  /// Ob SSL-Zertifikatsfehler ignoriert werden sollen (nur Development).
  final bool allowSslError;

  /// Ob detaillierte Debug-Logs aktiv sind.
  final bool debugLogs;

  /// Ob Query-Parameter zu einem einzelnen `qb64`-Parameter kollabiert
  /// werden sollen (Base64Url-kodiert).
  bool useBase64UrlParameter;

  /// Ob Backslashes in Ordnerpfaden doppelt prozentkodiert werden sollen.
  bool useFolderPathEncoding;

  /// Ob multi-fähige Requests tatsächlich über `v1/multi` gebündelt werden.
  ///
  /// Ein von `MultiRequestEligibility` als multi-fähig eingestufter Endpoint
  /// bleibt auch bei `false` gültig, wird dann aber direkt als Einzelanfrage
  /// gesendet. Damit ist die zentrale Eignungsprüfung unabhängig von diesem
  /// globalen Schalter, der lediglich die tatsächliche Aktivierung steuert.
  bool multiRequest;

  /// Session-ID zum Zeitpunkt der Erzeugung. Dient ausschließlich als
  /// Startwert für `SessionState` - der Runtime liest diesen Wert danach
  /// nicht mehr aus der Konfiguration.
  final String initialSessionId;

  /// Maximale Anzahl gepufferter Requests, bevor der `BatchCoordinator`
  /// (PR 3c) unabhängig vom Flush-Timer sofort flusht. Entspricht
  /// `RestApiDOCUframeConfig.maxBufferSize` (Legacy-Standard: 10).
  int maxBufferSize;

  /// Wartezeit in Millisekunden, bevor der `BatchCoordinator` (PR 3c)
  /// einen nicht-leeren, noch nicht vollen Buffer automatisch flusht.
  /// Entspricht `RestApiDOCUframeConfig.bufferFlushDelayMs`
  /// (Legacy-Standard: 100).
  int bufferFlushDelayMs;

  /// Anzahl der Elemente pro Seite bei paginierten Anfragen. Entspricht
  /// `RestApiDOCUframeConfig.perPageCount` (Legacy-Standard: 50).
  int perPageCount;

  RuntimeConfiguration({
    required this.serverUrl,
    required this.baseUri,
    required this.alias,
    required this.appKey,
    required this.userName,
    required this.appNames,
    required this.additionalAppNames,
    required this.device,
    required this.connectionTimeout,
    required this.responseTimeout,
    required this.allowSslError,
    required this.debugLogs,
    required this.useBase64UrlParameter,
    this.useFolderPathEncoding = false,
    required this.initialSessionId,
    this.multiRequest = false,
    this.maxBufferSize = 10,
    this.bufferFlushDelayMs = 100,
    this.perPageCount = 50,
  });

  /// Erstellt eine entkoppelte Momentaufnahme aus der (veränderlichen)
  /// Legacy-Konfiguration.
  factory RuntimeConfiguration.fromDocuframeConfig(
    RestApiDOCUframeConfig config,
  ) {
    return RuntimeConfiguration(
      serverUrl: config.serverUrl,
      baseUri: _normalizeBaseUri(config.serverUrl),
      alias: config.alias,
      appKey: config.appKey,
      userName: config.userName,
      appNames: List<String>.unmodifiable(config.appNames),
      additionalAppNames: List<String>.unmodifiable(config.additionalAppNames),
      device: config.device,
      connectionTimeout: config.connectionTimeout,
      responseTimeout: config.responseTimeout,
      allowSslError: config.allowSslError,
      debugLogs: config.debugLogs,
      useBase64UrlParameter: config.useBase64UrlParameter,
      useFolderPathEncoding: config.useFolderPathEncoding,
      initialSessionId: config.sessionId,
      multiRequest: config.multiRequest,
      maxBufferSize: config.maxBufferSize,
      bufferFlushDelayMs: config.bufferFlushDelayMs,
      perPageCount: config.perPageCount,
    );
  }

  /// Vollständige Liste aller Anwendungsnamen ([appNames] plus
  /// [additionalAppNames]) - Gegenstück zu
  /// `RestApiDOCUframeConfig.getAllAppNames()`.
  List<String> getAllAppNames() => [...appNames, ...additionalAppNames];

  /// Aktualisiert ausschließlich die explizit freigegebenen Laufzeitwerte.
  /// `null` bedeutet jeweils "unverändert"; Listen werden defensiv kopiert.
  void updateRuntimeSettings({
    List<String>? appNames,
    List<String>? additionalAppNames,
    bool? multiRequest,
    bool? useBase64UrlParameter,
    bool? useFolderPathEncoding,
    int? perPageCount,
    int? maxBufferSize,
    int? bufferFlushDelayMs,
  }) {
    if (perPageCount != null && perPageCount <= 0) {
      throw ArgumentError.value(
        perPageCount,
        'perPageCount',
        'muss größer als 0 sein',
      );
    }
    if (maxBufferSize != null && maxBufferSize <= 0) {
      throw ArgumentError.value(
        maxBufferSize,
        'maxBufferSize',
        'muss größer als 0 sein',
      );
    }
    if (bufferFlushDelayMs != null && bufferFlushDelayMs < 0) {
      throw ArgumentError.value(
        bufferFlushDelayMs,
        'bufferFlushDelayMs',
        'darf nicht negativ sein',
      );
    }

    if (appNames != null) {
      this.appNames = List<String>.unmodifiable(appNames);
    }
    if (additionalAppNames != null) {
      this.additionalAppNames = List<String>.unmodifiable(additionalAppNames);
    }
    this.multiRequest = multiRequest ?? this.multiRequest;
    this.useBase64UrlParameter =
        useBase64UrlParameter ?? this.useBase64UrlParameter;
    this.useFolderPathEncoding =
        useFolderPathEncoding ?? this.useFolderPathEncoding;
    this.perPageCount = perPageCount ?? this.perPageCount;
    this.maxBufferSize = maxBufferSize ?? this.maxBufferSize;
    this.bufferFlushDelayMs = bufferFlushDelayMs ?? this.bufferFlushDelayMs;
  }

  /// Ersetzt oder entfernt das für Login und Demo-Account verwendete Gerät.
  void setDevice(RestApiDevice? device) {
    this.device = device;
  }

  /// Parst die Server-URL und entfernt trailing Slashes aus dem Pfad,
  /// damit der URI-Aufbau keine doppelten Slashes erzeugt.
  static Uri _normalizeBaseUri(String serverUrl) {
    final Uri uri = Uri.parse(serverUrl);

    String path = uri.path;
    while (path.endsWith('/')) {
      path = path.substring(0, path.length - 1);
    }

    return path == uri.path ? uri : uri.replace(path: path);
  }
}
