import 'dart:typed_data';

import 'package:meta/meta.dart';

/// Transport-nahe, versionsunabhängige HTTP-Antwort.
///
/// Wird von `HttpTransport` erzeugt und von einer `IResponsePolicy` in ein
/// fachliches oder rohes Ergebnis (z.B. `GsdRawApiResponse`) übersetzt. Enthält
/// absichtlich kein `http.Response`, damit spätere V1-/V3-Response-Pipelines
/// nicht an die HTTP-Client-Bibliothek gekoppelt sind.
@internal
class TransportResponse {
  const TransportResponse({
    required this.statusCode,
    required this.headers,
    required this.bodyBytes,
    required this.body,
    this.reasonPhrase,
  });

  /// HTTP-Statuscode der Antwort.
  final int statusCode;

  /// Response-Header, wie vom Server geliefert.
  final Map<String, String> headers;

  /// Response-Body als Rohbytes.
  final Uint8List bodyBytes;

  /// Response-Body als dekodierter String.
  final String body;

  /// HTTP-Statusnachricht, sofern der Transport sie kennt.
  final String? reasonPhrase;
}
