import 'api_types.dart';

/// Beschreibt einen einzelnen [RawApi]-Request, bevor er gegen den internen
/// Runtime ausgeführt wird.
///
/// Diese Klasse ist ein reiner, unveränderlicher Werteträger. Die eigentliche
/// Pfadvalidierung (relativ, keine eigene Versions-/Alias-Präfix) übernimmt
/// `RawApi` selbst.
class RawApiRequest {
  /// API-Version, die das URL-Präfix (`v1`/`v2`) bestimmt.
  final ApiVersion version;

  /// HTTP-Methode der Anfrage.
  final ApiHttpMethod method;

  /// Pfad relativ zur konfigurierten DOCUframe-API (ohne eigenes
  /// Versions- oder Alias-Präfix).
  final String path;

  /// Optionale Query-Parameter.
  final Map<String, String>? queryParameters;

  /// Optionaler Request-Body.
  final String? body;

  /// Optionaler Content-Type; falls nicht gesetzt, verwendet der Runtime
  /// den Standard `application/json; charset=utf-8`.
  final String? contentType;

  /// Zusätzliche Header, die die Standard-Header des Runtime überschreiben
  /// können.
  final Map<String, String>? headers;

  const RawApiRequest({
    required this.version,
    required this.method,
    required this.path,
    this.queryParameters,
    this.body,
    this.contentType,
    this.headers,
  });

  @override
  String toString() =>
      'RawApiRequest(version: $version, method: $method, path: $path)';
}
