import 'package:gsd_restapi/src/models/gsd_http_method.dart';

/// Messwerte eines einzelnen HTTP-Requests (Dauer, Status, Größen).
///
/// Unveränderlich; der Client sendet eine Metrik je abgeschlossenem Request
/// über `GsdApiClient.httpMetrics`.
class GsdHttpMetric {
  /// Erstellt eine Metrik für den Request auf [path] mit [method].
  const GsdHttpMetric({
    required this.path,
    required this.method,
    this.startTime,
    this.stopTime,
    this.responseCode,
    this.requestPayloadSize,
    this.responsePayloadSize,
    this.responseContentType,
  });

  /// Pfad des Requests.
  final String path;

  /// HTTP-Methode des Requests.
  final GsdHttpMethod method;

  /// Startzeitpunkt des Requests.
  final DateTime? startTime;

  /// Endzeitpunkt des Requests.
  final DateTime? stopTime;

  /// HTTP-Statuscode der Antwort; `null` ohne Antwort.
  final int? responseCode;

  /// Größe des Request-Bodys in Bytes.
  final int? requestPayloadSize;

  /// Größe des Response-Bodys in Bytes.
  final int? responsePayloadSize;

  /// Content-Type der Antwort.
  final String? responseContentType;

  /// Dauer zwischen [startTime] und [stopTime]; `null`, solange eins davon
  /// fehlt.
  Duration? get duration {
    final start = startTime;
    final stop = stopTime;
    if (start != null && stop != null) {
      return stop.difference(start);
    }
    return null;
  }

  /// Gibt die Metrik als Map zurück.
  Map<String, dynamic> toMap() {
    return {
      'path': path,
      'method': method,
      'startTime': startTime?.toIso8601String(),
      'stopTime': stopTime?.toIso8601String(),
      'duration': duration?.inMilliseconds,
      'responseCode': responseCode,
      'requestPayloadSize': requestPayloadSize,
      'responsePayloadSize': responsePayloadSize,
      'responseContentType': responseContentType,
    };
  }
}
