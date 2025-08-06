// http_client_io.dart
import 'dart:io';
import 'package:gsd_restapi/httpclient/securehttpclientio.dart';
import 'package:http/http.dart' as http;

/// Erstellt einen HTTP-Client für Mobile- und Desktop-Plattformen
/// 
/// Verwendet den nativen Dart IO HttpClient für optimale Performance
/// auf Mobile- und Desktop-Plattformen. Unterstützt:
/// - Native Netzwerk-Features
/// - Erweiterte SSL/TLS-Konfiguration
/// - Proxy-Unterstützung
/// - Erweiterte Timeout-Kontrolle
/// 
/// [connectionTimeout] - Timeout für Verbindungsaufbau
/// [allowSslError] - Ob SSL-Zertifikatsfehler ignoriert werden sollen
/// 
/// Returns: SecureHttpClientIO für Mobile/Desktop-Plattformen
http.Client createPlatformClient(Duration connectionTimeout, {bool allowSslError = false}) {
  return SecureHttpClientIO(HttpClient()
    ..connectionTimeout = connectionTimeout
    ..badCertificateCallback = (X509Certificate cert, String host, int port) {
      // SSL-Zertifikatsfehler nur in Development-Modus ignorieren
      return allowSslError;
    }, allowSslError: allowSslError);
}
