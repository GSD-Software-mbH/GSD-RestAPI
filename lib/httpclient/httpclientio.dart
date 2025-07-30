// http_client_io.dart
import 'dart:io';
import 'package:restapi/httpclient/securehttpclientio.dart';
import 'package:http/http.dart' as http;

http.Client createPlatformClient(Duration connectionTimeout, {bool allowSslError = false}) {
  return SecureHttpClientIO(HttpClient()
    ..connectionTimeout = connectionTimeout
    ..badCertificateCallback = (X509Certificate cert, String host, int port) {

      return allowSslError;
    }, allowSslError: allowSslError);
}
