import 'package:gsd_restapi/src/exceptions/gsd_api_exception.dart';
import 'package:gsd_restapi/src/runtime/response/response_envelope.dart';
import 'package:meta/meta.dart';

/// Ergebnis von `GET v2/login/key`: der öffentliche RSA-Schlüssel des
/// Servers (PEM), mit dem der Login-Body verschlüsselt wird.
@internal
class LoginSecureKeyResult {
  const LoginSecureKeyResult(this.key);

  /// Liest `data.key` aus dem bereits ausgewerteten [envelope].
  ///
  /// Wirft [GsdParseException] mit `path: 'data.key'`, wenn der Schlüssel
  /// fehlt oder kein String ist.
  factory LoginSecureKeyResult.fromEnvelope(
    ResponseEnvelope envelope, {
    required String operationId,
  }) {
    final data = envelope.data;
    final key = data is Map<String, Object?> ? data['key'] : null;
    if (key is! String) {
      throw GsdParseException(operationId: operationId, path: 'data.key');
    }
    return LoginSecureKeyResult(key);
  }

  /// Der öffentliche Schlüssel des Servers als PEM.
  final String key;
}
