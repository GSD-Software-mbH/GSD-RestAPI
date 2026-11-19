import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/gsd_http_metric.dart';
import 'package:gsd_restapi/src/runtime/runtime_events.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:meta/meta.dart';

/// Strukturiertes Logging und Metriken für den neuen Runtime.
///
/// Emittiert Ereignisse (`requestStarted`/`requestSucceeded`/
/// `requestFailed`) über [RuntimeEvents.logs] und
/// [RuntimeEvents.httpMetrics] (als [GsdHttpMetric]).
///
/// Redaction: Die Werte der Header `sessionid` und `appkey` sowie Request-
/// und Response-Bodies werden niemals wörtlich geloggt - stattdessen werden
/// nur Längenangaben bzw. Redaction-Marker ausgegeben.
@internal
class RuntimeTelemetry {
  RuntimeTelemetry({RuntimeEvents? events}) : _events = events;

  /// Header-Namen (kleingeschrieben), deren Werte redigiert werden.
  static const Set<String> _redactedHeaderNames = {'sessionid', 'appkey'};

  final RuntimeEvents? _events;

  /// Meldet den Start eines Requests und liefert einen Tracker, über den
  /// der Ausgang (`succeeded`/`failed`) gemeldet wird.
  ApiRequestTelemetry requestStarted({
    required String operationId,
    required GsdHttpMethod method,
    required Uri uri,
    Map<String, String>? headers,
    String? body,
  }) {
    final startTime = DateTime.now();

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
      startTime: startTime,
      requestPayloadSize: body?.length,
    );
  }

  /// Redigiert die WERTE aller Query-Parameter einer URI (die Schlüssel
  /// bleiben lesbar). Query-Werte können fachliche Daten enthalten
  /// (Suchbegriffe, Serialisierungen, im qb64-Modus die komplette
  /// kodierte Query) und gehören daher nicht ins Log.
  String redactUri(Uri uri) {
    // '?' kann vor der Query in keiner anderen URI-Komponente auftreten
    // (unsere URIs haben kein Fragment) - der Split ist daher sicher.
    final base = uri.toString().split('?').first;

    if (uri.query.isEmpty) {
      return base;
    }

    final redactedQuery = uri.queryParameters.keys
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

  void _log(String message) {
    _events?.log(message);
  }

  void _recordMetric(GsdHttpMetric metric) {
    _events?.httpMetric(metric);
  }
}

/// Tracker für einen einzelnen laufenden Request; meldet Erfolg oder
/// Fehlschlag genau einmal (weitere Aufrufe sind No-Ops).
@internal
class ApiRequestTelemetry {
  ApiRequestTelemetry._({
    required RuntimeTelemetry telemetry,
    required String operationId,
    required GsdHttpMethod method,
    required Uri uri,
    required DateTime startTime,
    required int? requestPayloadSize,
  }) : _telemetry = telemetry,
       _operationId = operationId,
       _method = method,
       _uri = uri,
       _startTime = startTime,
       _requestPayloadSize = requestPayloadSize;
  final RuntimeTelemetry _telemetry;
  final String _operationId;
  final GsdHttpMethod _method;
  final Uri _uri;
  final DateTime _startTime;
  final int? _requestPayloadSize;
  final Stopwatch _stopwatch = Stopwatch()..start();
  bool _completed = false;

  /// Meldet den erfolgreichen Abschluss (HTTP-Antwort liegt vor,
  /// unabhängig vom Statuscode).
  void succeeded(TransportResponse response) {
    if (_completed) {
      return;
    }
    _completed = true;
    _stopwatch.stop();
    final stopTime = DateTime.now();

    _telemetry._log(
      'Request succeeded: operationId=$_operationId '
      'method=${_method.name.toUpperCase()} uri=${_telemetry.redactUri(_uri)} '
      'durationMs=${_stopwatch.elapsedMilliseconds} '
      'statusCode=${response.statusCode} '
      'bodyLength=${response.bodyBytes.length}',
    );

    _recordMetric(stopTime, response);
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
    final stopTime = DateTime.now();

    _telemetry._log(
      'Request failed: operationId=$_operationId '
      'method=${_method.name.toUpperCase()} uri=${_telemetry.redactUri(_uri)} '
      'durationMs=${_stopwatch.elapsedMilliseconds} '
      '${response != null ? 'statusCode=${response.statusCode} ' : ''}'
      'error=$error',
    );

    _recordMetric(stopTime, response);
  }

  /// Sendet die Metrik; auch im Fehlerfall, `responseCode` nur mit Antwort.
  /// HEAD erzeugt wie bisher keine Metrik.
  void _recordMetric(DateTime stopTime, TransportResponse? response) {
    if (_method == GsdHttpMethod.head) {
      return;
    }

    _telemetry._recordMetric(
      GsdHttpMetric(
        path: _uri.path,
        method: _method,
        startTime: _startTime,
        stopTime: stopTime,
        responseCode: response?.statusCode,
        requestPayloadSize: _requestPayloadSize,
        responsePayloadSize: response?.bodyBytes.length,
        responseContentType: response?.headers['content-type'],
      ),
    );
  }
}
