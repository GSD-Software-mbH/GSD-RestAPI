import 'dart:typed_data';

import 'package:meta/meta.dart';

/// Transport-nahe, versionsunabhängige HTTP-Antwort.
///
/// Wird von `HttpTransport` erzeugt und von einer `ResponsePolicy` in ein
/// fachliches oder rohes Ergebnis (z.B. `RawApiResponse`) übersetzt. Enthält
/// absichtlich kein `http.Response`, damit spätere V1-/V2-Response-Pipelines
/// nicht an die HTTP-Client-Bibliothek gekoppelt sind.
@internal
class TransportResponse {
  /// HTTP-Statuscode der Antwort.
  final int statusCode;

  /// Response-Header, wie vom Server geliefert.
  final Map<String, String> headers;

  /// Response-Body als Rohbytes.
  final Uint8List bodyBytes;

  /// Response-Body als dekodierter String.
  final String body;

  const TransportResponse({
    required this.statusCode,
    required this.headers,
    required this.bodyBytes,
    required this.body,
  });
}
