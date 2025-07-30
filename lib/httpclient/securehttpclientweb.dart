import 'dart:convert';
import 'dart:typed_data';
import 'package:http/browser_client.dart';
import 'package:http/http.dart' as http;
import 'package:restapi/exception/securityexception.dart';


class SecureHttpClientWeb extends BrowserClient {
  final bool allowSslError;

  SecureHttpClientWeb({this.allowSslError = false});

  void _validateUrl(Uri url) {
    if (url.scheme == 'http' && !allowSslError) {
      throw SecurityException(
        'HTTP connections are not allowed (SSL errors are not allowed).'
      );
    }
  }

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    _validateUrl(request.url);
    return super.send(request);
  }

  @override
  Future<http.Response> get(Uri url, {Map<String, String>? headers}) async {
    _validateUrl(url);
    return super.get(url, headers: headers);
  }

  @override
  Future<http.Response> post(Uri url, {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
    _validateUrl(url);
    return super.post(url, headers: headers, body: body, encoding: encoding);
  }

  @override
  Future<http.Response> put(Uri url, {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
    _validateUrl(url);
    return super.put(url, headers: headers, body: body, encoding: encoding);
  }

  @override
  Future<http.Response> patch(Uri url, {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
    _validateUrl(url);
    return super.patch(url, headers: headers, body: body, encoding: encoding);
  }

  @override
  Future<http.Response> delete(Uri url, {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
    _validateUrl(url);
    return super.delete(url, headers: headers, body: body, encoding: encoding);
  }

  @override
  Future<http.Response> head(Uri url, {Map<String, String>? headers}) async {
    _validateUrl(url);
    return super.head(url, headers: headers);
  }

  @override
  Future<String> read(Uri url, {Map<String, String>? headers}) async {
    _validateUrl(url);
    return super.read(url, headers: headers);
  }

  @override
  Future<Uint8List> readBytes(Uri url, {Map<String, String>? headers}) async {
    _validateUrl(url);
    return super.readBytes(url, headers: headers);
  }
}