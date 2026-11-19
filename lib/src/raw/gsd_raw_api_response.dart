import 'dart:typed_data';
import 'package:gsd_restapi/src/raw/gsd_raw_api.dart';

/// Stabile, transport-unabhängige Antwort von [GsdRawApi].
///
/// Enthält bewusst kein `http.Response`, damit Aufrufer nicht an die
/// zugrunde liegende HTTP-Client-Bibliothek gekoppelt werden. Eine
/// Raw-Antwort wird nicht in fachliche Modelle gemappt: HTTP-Fehlerstatus
/// (z.B. 4xx/5xx) werden als [GsdRawApiResponse] zurückgegeben, nicht
/// geworfen. Nur Transport-Fehler (Timeout, Netzwerk) werfen eine
/// Exception.
class GsdRawApiResponse {
  /// Erstellt eine Raw-Antwort.
  const GsdRawApiResponse({
    required this.statusCode,
    required this.headers,
    required this.body,
    required this.bodyBytes,
  });

  /// HTTP-Statuscode der Antwort.
  final int statusCode;

  /// Response-Header, wie vom Server geliefert.
  final Map<String, String> headers;

  /// Response-Body als dekodierter String.
  final String body;

  /// Response-Body als Rohbytes.
  final Uint8List bodyBytes;

  @override
  String toString() =>
      'GsdRawApiResponse(statusCode: $statusCode, bodyLength: ${body.length})';
}
