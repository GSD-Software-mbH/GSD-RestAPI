// http_client_stub.dart
import 'package:http/http.dart' as http;

http.Client createPlatformClient(Duration connectionTimeout, {bool allowSslError = false}) {
  throw UnsupportedError('No HTTP client available for this platform.');
}
