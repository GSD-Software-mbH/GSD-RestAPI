// http_client_web.dart
import 'package:http/http.dart' as http;
import 'package:restapi/httpclient/securehttpclientweb.dart';

http.Client createPlatformClient(Duration connectionTimeout, {bool allowSslError = false}) {
  // Der connectionTimeout wird hier nicht berücksichtigt,
  // da BrowserClient dies nicht unterstützt.
  return SecureHttpClientWeb(allowSslError: allowSslError);
}
