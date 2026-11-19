import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

/// Platzhalter für Plattformen ohne `dart.library.io` und ohne
/// `dart.library.js_interop`.
@internal
abstract final class HttpClientFactory {
  /// Wirft immer: Auf dieser Plattform gibt es keinen HTTP-Client.
  static http.Client create(
    Duration connectionTimeout, {
    bool allowSslError = false,
  }) {
    throw UnsupportedError('No HTTP client available for this platform.');
  }
}
