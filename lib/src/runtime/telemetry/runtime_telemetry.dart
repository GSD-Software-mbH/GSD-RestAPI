import 'package:meta/meta.dart';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/raw/api_types.dart';

import '../transport_response.dart';

/// Strukturiertes Logging und Metriken für den neuen Runtime.
///
/// Emittiert Ereignisse (`requestStarted`/`requestSucceeded`/
/// `requestFailed`) über die vorhandenen Callback-Typen
/// ([RestApiDOCUframeCallbacks.onLogMessage] und
/// [RestApiDOCUframeCallbacks.onHttpMetricRecorded] via
/// [RestApiHttpMetric]).
///
/// Redaction: Die Werte der Header `sessionid` und `appkey` sowie Request-
/// und Response-Bodies werden niemals wörtlich geloggt - stattdessen werden
/// nur Längenangaben bzw. Redaction-Marker ausgegeben.
@internal
class RuntimeTelemetry {
  /// Header-Namen (kleingeschrieben), deren Werte redigiert werden.
  static const Set<String> _redactedHeaderNames = {'sessionid', 'appkey'};

  final RestApiDOCUframeCallbacks? _callbacks;

  RuntimeTelemetry({RestApiDOCUframeCallbacks? callbacks})
    : _callbacks = callbacks;

  /// Meldet den Start eines Requests und liefert einen Tracker, über den
  /// der Ausgang (`succeeded`/`failed`) gemeldet wird.
  ApiRequestTelemetry requestStarted({
    required String operationId,
    required ApiHttpMethod method,
    required Uri uri,
    Map<String, String>? headers,
    String? body,
  }) {
    final RestApiHttpMetric? metric = _createMetric(uri, method);
    metric?.requestPayloadSize = body?.length;
    metric?.start();

    _log(
      'Request started: operationId=$operationId '
      'method=${method.name.toUpperCase()} uri=${redactUri(uri)} '
      'headers=${redactHeaders(headers)} bodyLength=${body?.length ?? 0}',
    );

    return ApiRequestTelemetry._(
      telemetry: this,
      operationId: operationId,
      method: method,
      uri: uri,
      metric: metric,
    );
  }

  /// Redigiert die WERTE aller Query-Parameter einer URI (die Schlüssel
  /// bleiben lesbar). Query-Werte können fachliche Daten enthalten
  /// (Suchbegriffe, Serialisierungen, im qb64-Modus die komplette
  /// kodierte Query) und gehören daher nicht ins Log.
  String redactUri(Uri uri) {
    // '?' kann vor der Query in keiner anderen URI-Komponente auftreten
    // (unsere URIs haben kein Fragment) - der Split ist daher sicher.
    final String base = uri.toString().split('?').first;

    if (uri.query.isEmpty) {
      return base;
    }

    final String redactedQuery = uri.queryParameters.keys
        .map((key) => '$key=[REDACTED]')
        .join('&');

    return '$base?$redactedQuery';
  }

  /// Redigiert sensible Header-Werte (`sessionid`, `appkey`,
  /// case-insensitive) zu einem Marker mit Längenangabe.
  Map<String, String> redactHeaders(Map<String, String>? headers) {
    if (headers == null) {
      return const {};
    }

    return headers.map((key, value) {
      if (_redactedHeaderNames.contains(key.toLowerCase())) {
        return MapEntry(key, '[REDACTED len=${value.length}]');
      }
      return MapEntry(key, value);
    });
  }

  /// Erstellt die Legacy-Metrik; `null` für Methoden ohne Entsprechung im
  /// Legacy-Enum [HttpMethod] (aktuell nur HEAD).
  RestApiHttpMetric? _createMetric(Uri uri, ApiHttpMethod method) {
    final HttpMethod? legacyMethod = switch (method) {
      ApiHttpMethod.get => HttpMethod.get,
      ApiHttpMethod.post => HttpMethod.post,
      ApiHttpMethod.put => HttpMethod.put,
      ApiHttpMethod.patch => HttpMethod.patch,
      ApiHttpMethod.delete => HttpMethod.delete,
      ApiHttpMethod.head => null,
    };

    if (legacyMethod == null) {
      return null;
    }

    return RestApiHttpMetric(uri.path, legacyMethod);
  }

  void _log(String message) {
    _callbacks?.triggerLogEvent(message);
  }

  void _recordMetric(RestApiHttpMetric metric) {
    _callbacks?.triggerHttpMetricRecordedEvent(metric);
  }
}

/// Tracker für einen einzelnen laufenden Request; meldet Erfolg oder
/// Fehlschlag genau einmal (weitere Aufrufe sind No-Ops).
@internal
class ApiRequestTelemetry {
  final RuntimeTelemetry _telemetry;
  final String _operationId;
  final ApiHttpMethod _method;
  final Uri _uri;
  final RestApiHttpMetric? _metric;
  final Stopwatch _stopwatch = Stopwatch()..start();
  bool _completed = false;

  ApiRequestTelemetry._({
    required RuntimeTelemetry telemetry,
    required String operationId,
    required ApiHttpMethod method,
    required Uri uri,
    required RestApiHttpMetric? metric,
  }) : _telemetry = telemetry,
       _operationId = operationId,
       _method = method,
       _uri = uri,
       _metric = metric;

  /// Meldet den erfolgreichen Abschluss (HTTP-Antwort liegt vor,
  /// unabhängig vom Statuscode).
  void succeeded(TransportResponse response) {
    if (_completed) {
      return;
    }
    _completed = true;
    _stopwatch.stop();

    _metric?.responseCode = response.statusCode;
    _metric?.responsePayloadSize = response.bodyBytes.length;
    _metric?.responseContentType = response.headers['content-type'];
    _metric?.stop();

    _telemetry._log(
      'Request succeeded: operationId=$_operationId '
      'method=${_method.name.toUpperCase()} uri=${_telemetry.redactUri(_uri)} '
      'durationMs=${_stopwatch.elapsedMilliseconds} '
      'statusCode=${response.statusCode} '
      'bodyLength=${response.bodyBytes.length}',
    );

    if (_metric != null) {
      _telemetry._recordMetric(_metric);
    }
  }

  /// Meldet einen Fehlschlag: entweder ein Transport-Fehler (Timeout,
  /// Netzwerk; kein [response]) oder ein Dekodier-/Mapping-Fehler nach
  /// erhaltener HTTP-Antwort ([response] gesetzt, z.B. das
  /// V1-Exception-Mapping).
  ///
  /// Die Metrik wird - wie im Legacy-Manager (`finally`-Block) - auch im
  /// Fehlerfall emittiert; `responseCode` ist nur gesetzt, wenn eine
  /// HTTP-Antwort vorlag.
  void failed(Object error, {TransportResponse? response}) {
    if (_completed) {
      return;
    }
    _completed = true;
    _stopwatch.stop();

    if (response != null) {
      _metric?.responseCode = response.statusCode;
      _metric?.responsePayloadSize = response.bodyBytes.length;
      _metric?.responseContentType = response.headers['content-type'];
    }
    _metric?.stop();

    _telemetry._log(
      'Request failed: operationId=$_operationId '
      'method=${_method.name.toUpperCase()} uri=${_telemetry.redactUri(_uri)} '
      'durationMs=${_stopwatch.elapsedMilliseconds} '
      '${response != null ? 'statusCode=${response.statusCode} ' : ''}'
      'error=$error',
    );

    if (_metric != null) {
      _telemetry._recordMetric(_metric);
    }
  }
}
