import 'dart:convert';
import 'dart:typed_data';
import 'package:http/browser_client.dart';
import 'package:http/http.dart' as http;
import 'package:restapi/restapi.dart';

/// Sicherer HTTP-Client für Web-Plattformen
/// 
/// Erweitert den Standard-BrowserClient um Sicherheitsvalidierung:
/// - Verhindert unverschlüsselte HTTP-Verbindungen (außer explizit erlaubt)
/// - Validiert URLs vor jeder Anfrage
/// - Wirft SecurityException bei unsicheren Verbindungen
/// - Unterliegt Browser-Sicherheitsrichtlinien (CORS, Mixed Content, etc.)
/// 
/// Verwendet die nativen Browser-APIs für HTTP-Kommunikation.
class SecureHttpClientWeb extends BrowserClient {
  /// Ob unsichere HTTP-Verbindungen erlaubt sind
  /// 
  /// Sollte nur in Development-Umgebungen auf true gesetzt werden.
  /// In Production sollte immer HTTPS verwendet werden.
  /// Beachte: Browser können HTTP-Verbindungen auch unabhängig blockieren.
  final bool allowSslError;

  /// Erstellt einen neuen SecureHttpClientWeb
  /// 
  /// [allowSslError] - Ob HTTP-Verbindungen erlaubt sind (Standard: false)
  SecureHttpClientWeb({this.allowSslError = false});

  /// Validiert eine URL auf Sicherheit
  /// 
  /// Überprüft, ob die URL HTTPS verwendet oder HTTP explizit erlaubt ist.
  /// 
  /// [url] - Die zu validierende URL
  /// 
  /// Throws: SecurityException wenn HTTP nicht erlaubt ist
  void _validateUrl(Uri url) {
    if (url.scheme == 'http' && !allowSslError) {
      throw SecurityException(
        'HTTP connections are not allowed (SSL errors are not allowed).'
      );
    }
  }

  /// Sendet eine HTTP-Anfrage mit URL-Validierung
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    _validateUrl(request.url);
    return super.send(request);
  }

  /// GET-Anfrage mit URL-Validierung
  @override
  Future<http.Response> get(Uri url, {Map<String, String>? headers}) async {
    _validateUrl(url);
    return super.get(url, headers: headers);
  }

  /// POST-Anfrage mit URL-Validierung
  @override
  Future<http.Response> post(Uri url, {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
    _validateUrl(url);
    return super.post(url, headers: headers, body: body, encoding: encoding);
  }

  /// PUT-Anfrage mit URL-Validierung
  @override
  Future<http.Response> put(Uri url, {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
    _validateUrl(url);
    return super.put(url, headers: headers, body: body, encoding: encoding);
  }

  /// PATCH-Anfrage mit URL-Validierung
  @override
  Future<http.Response> patch(Uri url, {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
    _validateUrl(url);
    return super.patch(url, headers: headers, body: body, encoding: encoding);
  }

  /// DELETE-Anfrage mit URL-Validierung
  @override
  Future<http.Response> delete(Uri url, {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
    _validateUrl(url);
    return super.delete(url, headers: headers, body: body, encoding: encoding);
  }

  /// HEAD-Anfrage mit URL-Validierung
  @override
  Future<http.Response> head(Uri url, {Map<String, String>? headers}) async {
    _validateUrl(url);
    return super.head(url, headers: headers);
  }

  /// Liest URL-Inhalt als String mit URL-Validierung
  @override
  Future<String> read(Uri url, {Map<String, String>? headers}) async {
    _validateUrl(url);
    return super.read(url, headers: headers);
  }

  /// Liest URL-Inhalt als Bytes mit URL-Validierung
  @override
  Future<Uint8List> readBytes(Uri url, {Map<String, String>? headers}) async {
    _validateUrl(url);
    return super.readBytes(url, headers: headers);
  }
}