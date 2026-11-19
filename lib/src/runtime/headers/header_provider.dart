import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:gsd_restapi/src/runtime/session/session_state.dart';
import 'package:meta/meta.dart';

/// Erzeugt die HTTP-Header eines Requests mit den exakten
/// Legacy-Header-Namen.
///
/// Header-Namen (Groß-/Kleinschreibung wie im Legacy-Manager):
/// - `Content-type`: Standard `application/json; charset=utf-8`; ein leerer
///   Content-Type unterdrückt den Header vollständig.
/// - `appkey`: immer gesetzt.
/// - `sessionid`: nur bei [AuthenticationPolicy.session] bzw.
///   [AuthenticationPolicy.sessionNoRefresh] und nicht-leerer Session-ID
///   im [SessionState].
///
/// Zusätzliche Header überschreiben bei Namensgleichheit die
/// Standard-Header.
@internal
class HeaderProvider {
  const HeaderProvider({
    required this.configuration,
    required this.sessionState,
  });

  /// Standard-Content-Type des Legacy-Vertrags.
  static const String defaultContentType = 'application/json; charset=utf-8';

  /// Unveränderliche Konfiguration (App-Key).
  final RuntimeConfiguration configuration;

  /// Laufender Session-Zustand; wird bei jedem [build] frisch gelesen.
  final SessionState sessionState;

  /// Baut die Header für einen Request.
  ///
  /// [contentType] - `null` verwendet [defaultContentType], ein leerer
  /// String unterdrückt den `Content-type`-Header.
  /// [additionalHeaders] - gewinnen bei Namensgleichheit.
  Map<String, String> build({
    required AuthenticationPolicy authentication,
    String? contentType,
    Map<String, String>? additionalHeaders,
  }) {
    final headers = <String, String>{};

    final effectiveContentType = contentType ?? defaultContentType;
    if (effectiveContentType.isNotEmpty) {
      headers['Content-type'] = effectiveContentType;
    }

    headers['appkey'] = configuration.appKey;

    if (authentication != AuthenticationPolicy.none &&
        sessionState.sessionId.isNotEmpty) {
      headers['sessionid'] = sessionState.sessionId;
    }

    if (additionalHeaders != null) {
      headers.addAll(additionalHeaders);
    }

    return headers;
  }
}
