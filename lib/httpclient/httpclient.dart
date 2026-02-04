import 'package:http/http.dart' as http;

import 'httpclientstub.dart'
    if (dart.library.io) 'httpclientio.dart'
    if (dart.library.html) 'httpclientweb.dart';

/// Erstellt einen plattformspezifischen HTTP-Client
///
/// Diese Factory-Funktion erstellt automatisch den passenden HTTP-Client
/// basierend auf der aktuellen Plattform:
/// - Mobile/Desktop: IOClient mit nativen Networking-Features
/// - Web: BrowserClient für Web-basierte Anfragen
///
/// [connectionTimeout] - Timeout für Verbindungsaufbau
/// [allowSslError] - Ob SSL-Zertifikatsfehler ignoriert werden sollen (nur Development)
///
/// Returns: Plattformspezifischer HTTP-Client
http.Client createClient(
  Duration connectionTimeout, {
  bool allowSslError = false,
}) => createPlatformClient(connectionTimeout, allowSslError: allowSslError);
