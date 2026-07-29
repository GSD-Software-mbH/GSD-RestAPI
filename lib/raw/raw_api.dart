import '../src/runtime/api_request.dart';
import '../src/runtime/api_runtime.dart';
import '../src/runtime/execution/runtime_execution_context.dart';
import '../src/runtime/policies/authentication_policy.dart';
import '../src/runtime/policies/raw_session_aware_response_policy.dart';
import 'api_types.dart';
import 'raw_api_request.dart';
import 'raw_api_response.dart';

/// Kontrollierter Escape Hatch für kundenspezifische oder noch nicht nativ
/// unterstützte DOCUframe-Endpunkte.
///
/// - Base-URL, Alias, Header, Session, Logging und Timeouts laufen über den
///   neuen internen Runtime.
/// - [ApiVersion] ist verpflichtend und bestimmt das URL-Präfix (`v1`/`v2`).
/// - Pfade sind relativ zur konfigurierten DOCUframe-API; absolute URLs,
///   Pfad-Traversierung sowie eigene Versions- oder Alias-Präfixe im Pfad
///   werden abgelehnt.
/// - Die Rückgabe ist ein stabiles [RawApiResponse]; HTTP-Fehlerstatus
///   werden zurückgegeben, nicht geworfen. Recoverbare DOCUframe-Sessionfehler
///   (`201`, `204`, `341`) lösen bei vorhandenen Login-Credentials einmalig
///   einen Session-Refresh samt Retry aus. Transport-Fehler (Timeout,
///   Netzwerk) werfen eine Exception.
/// - Eine Raw-Antwort wird nicht in fachliche Modelle gemappt. Jeder
///   dokumentierte V1-/V2-Endpunkt wird weiterhin typisiert implementiert;
///   native Endpoints dürfen [RawApi] nicht intern verwenden.
class RawApi {
  final ApiRuntime _runtime;

  /// Erstellt eine [RawApi] auf einem bestehenden Runtime.
  ///
  /// Wird üblicherweise über `DOCUframeApi.raw` verwendet.
  RawApi(ApiRuntime runtime) : _runtime = runtime;

  /// Führt einen versionsgebundenen, relativen Request aus.
  ///
  /// [path] - Pfad relativ zur konfigurierten DOCUframe-API, ohne Versions-
  /// und ohne Alias-Präfix (beides ergänzt der Runtime); mit oder ohne
  /// führenden `/`.
  /// [headers] - zusätzliche Header; überschreiben bei Namensgleichheit die
  /// Standard-Header.
  ///
  /// Wirft [ArgumentError] bei ungültigem Pfad (absolute URL, Schema,
  /// `..`-Traversierung, Backslashes (roh oder als `%5c`), eigenem
  /// `v1`/`v2`- oder Alias-Präfix, Query oder Fragment im Pfad) und
  /// [StateError], wenn der zugehörige Runtime bereits freigegeben wurde.
  Future<RawApiResponse> request({
    required ApiVersion version,
    required ApiHttpMethod method,
    required String path,
    Map<String, String>? queryParameters,
    String? body,
    String? contentType,
    Map<String, String>? headers,
  }) {
    final rawRequest = RawApiRequest(
      version: version,
      method: method,
      path: path,
      queryParameters: queryParameters,
      body: body,
      contentType: contentType,
      headers: headers,
    );

    _validatePath(rawRequest.path);

    // Raw ist NIE Multi-Request-fähig, unabhängig vom angefragten Pfad
    // (derselbe Pfad kann über einen nativen Endpoint durchaus multi-fähig
    // sein). Dies läuft daher über eine interne No-Buffer-Runtime-Grenze
    // statt über eine öffentliche Per-Request-Buffering-Option.
    return RuntimeExecutionContext.runWithoutBuffering(
      () => _runtime.execute(
        ApiRequest<RawApiResponse>(
          method: rawRequest.method,
          version: rawRequest.version,
          path: rawRequest.path,
          queryParameters: rawRequest.queryParameters,
          body: rawRequest.body,
          contentType: rawRequest.contentType,
          additionalHeaders: rawRequest.headers,
          authentication: AuthenticationPolicy.session,
          responsePolicy: const RawSessionAwareResponsePolicy(),
          operationId: 'raw.${version.name}.${method.name}',
        ),
      ),
    );
  }

  /// Validiert, dass [path] ein relativer API-Pfad ohne eigenes Versions-
  /// oder Alias-Präfix ist.
  void _validatePath(String path) {
    if (path.trim().isEmpty) {
      throw ArgumentError.value(path, 'path', 'Pfad darf nicht leer sein.');
    }

    final Uri? parsed = Uri.tryParse(path);
    if (parsed == null || parsed.hasScheme || parsed.hasAuthority) {
      throw ArgumentError.value(
        path,
        'path',
        'Nur relative Pfade sind erlaubt; absolute URLs, Schemas und '
            'Hosts werden abgelehnt.',
      );
    }

    if (path.contains('?') || path.contains('#')) {
      throw ArgumentError.value(
        path,
        'path',
        'Query und Fragment gehören nicht in den Pfad; '
            'queryParameters verwenden.',
      );
    }

    // Backslashes werden von Dart's Uri NICHT normalisiert und könnten von
    // Windows-/IIS-basierten Servern als Segmenttrenner interpretiert
    // werden ("..\..\x" bzw. "..%5c..%5cx" als Traversal-Bypass). Ablehnen
    // ist sicherer als Normalisieren.
    if (path.contains(r'\') || path.toLowerCase().contains('%5c')) {
      throw ArgumentError.value(
        path,
        'path',
        'Backslashes (roh oder prozentkodiert als %5c) sind im Pfad '
            'nicht erlaubt.',
      );
    }

    final List<String> segments = path
        .split('/')
        .where((segment) => segment.isNotEmpty)
        .toList();

    if (segments.isEmpty) {
      throw ArgumentError.value(path, 'path', 'Pfad darf nicht leer sein.');
    }

    if (segments.any((segment) => segment == '..')) {
      throw ArgumentError.value(
        path,
        'path',
        'Pfad-Traversierung ("..") ist nicht erlaubt.',
      );
    }

    final String firstSegment = segments.first.toLowerCase();
    if (firstSegment == 'v1' || firstSegment == 'v2') {
      throw ArgumentError.value(
        path,
        'path',
        'Die API-Version gehört nicht in den Pfad; sie wird ausschließlich '
            'über den version-Parameter bestimmt.',
      );
    }

    final String alias = _runtime.configuration.alias.toLowerCase();
    if (alias.isNotEmpty && segments.first.toLowerCase() == alias) {
      throw ArgumentError.value(
        path,
        'path',
        'Der Alias gehört nicht in den Pfad; er kommt aus der '
            'Konfiguration.',
      );
    }
  }
}
