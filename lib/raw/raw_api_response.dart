import 'dart:typed_data';

/// Stabile, transport-unabhängige Antwort von [RawApi].
///
/// Enthält bewusst kein `http.Response`, damit Aufrufer nicht an die
/// zugrunde liegende HTTP-Client-Bibliothek gekoppelt werden. Eine
/// Raw-Antwort wird nicht in fachliche Modelle gemappt: HTTP-Fehlerstatus
/// (z.B. 4xx/5xx) werden als [RawApiResponse] zurückgegeben, nicht
/// geworfen. Nur Transport-Fehler (Timeout, Netzwerk) werfen eine
/// Exception.
class RawApiResponse {
  /// HTTP-Statuscode der Antwort.
  final int statusCode;

  /// Response-Header, wie vom Server geliefert.
  final Map<String, String> headers;

  /// Response-Body als dekodierter String.
  final String body;

  /// Response-Body als Rohbytes.
  final Uint8List bodyBytes;

  const RawApiResponse({
    required this.statusCode,
    required this.headers,
    required this.body,
    required this.bodyBytes,
  });

  @override
  String toString() =>
      'RawApiResponse(statusCode: $statusCode, bodyLength: ${body.length})';
}
