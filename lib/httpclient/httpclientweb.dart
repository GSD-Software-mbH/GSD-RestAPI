// http_client_web.dart
import 'package:http/http.dart' as http;
import 'package:gsd_restapi/httpclient/securehttpclientweb.dart';

/// Erstellt einen HTTP-Client für Web-Plattformen
/// 
/// Verwendet den Browser-basierten HTTP-Client für Web-Anwendungen.
/// Arbeitet mit den nativen Browser-APIs und unterliegt den
/// Browser-Sicherheitsrichtlinien (CORS, etc.).
/// 
/// Hinweis: Der connectionTimeout wird hier nicht berücksichtigt,
/// da der BrowserClient dies nicht direkt unterstützt.
/// 
/// [connectionTimeout] - Wird ignoriert (Browser-Limitation)
/// [allowSslError] - SSL-Konfiguration (Browser-abhängig)
/// 
/// Returns: SecureHttpClientWeb für Web-Plattformen
http.Client createPlatformClient(Duration connectionTimeout, {bool allowSslError = false}) {
  // Der connectionTimeout wird hier nicht berücksichtigt,
  // da BrowserClient dies nicht unterstützt.
  return SecureHttpClientWeb(allowSslError: allowSslError);
}
