// http_client_stub.dart
import 'package:http/http.dart' as http;

/// Stub-Implementation für nicht unterstützte Plattformen
/// 
/// Diese Funktion wird als Fallback verwendet, wenn weder dart:io
/// noch dart:html verfügbar sind. In der Praxis sollte dies nie
/// aufgerufen werden, da Flutter alle unterstützten Plattformen
/// abdeckt.
/// 
/// [connectionTimeout] - Wird nicht verwendet
/// [allowSslError] - Wird nicht verwendet
/// 
/// Throws: UnsupportedError - Immer, da keine Implementation verfügbar
http.Client createPlatformClient(Duration connectionTimeout, {bool allowSslError = false}) {
  throw UnsupportedError('No HTTP client available for this platform.');
}
