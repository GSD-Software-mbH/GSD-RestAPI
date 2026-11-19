import 'package:http/browser_client.dart';
import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

/// Erstellt den HTTP-Client für Web-Plattformen.
@internal
abstract final class HttpClientFactory {
  /// Ein `BrowserClient`.
  ///
  /// [connectionTimeout] und [allowSslError] gelten hier nicht: Den
  /// Verbindungsaufbau und die Zertifikate prüft der Browser.
  static http.Client create(
    Duration connectionTimeout, {
    bool allowSslError = false,
  }) {
    return BrowserClient();
  }
}
