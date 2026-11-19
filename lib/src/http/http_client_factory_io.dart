import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:meta/meta.dart';

/// Erstellt den HTTP-Client für Mobile- und Desktop-Plattformen.
@internal
abstract final class HttpClientFactory {
  /// Ein `IOClient` über den nativen `HttpClient`.
  ///
  /// [connectionTimeout] - Timeout für den Verbindungsaufbau
  /// [allowSslError] - Ob SSL-Zertifikatsfehler ignoriert werden sollen
  static http.Client create(
    Duration connectionTimeout, {
    bool allowSslError = false,
  }) {
    return IOClient(
      HttpClient()
        ..connectionTimeout = connectionTimeout
        ..badCertificateCallback = (cert, host, port) {
          // SSL-Zertifikatsfehler nur in Development-Modus ignorieren
          return allowSslError;
        },
    );
  }
}
