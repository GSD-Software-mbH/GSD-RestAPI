import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:restapi/exception/securityexception.dart';


class SecureHttpClientIO extends IOClient {
  final bool allowSslError;

  SecureHttpClientIO(super.inner, {this.allowSslError = false});

  void _validateUrl(Uri url) {
    if (url.scheme == 'http' && !allowSslError) {
      throw SecurityException(
        'HTTP connections are not allowed (SSL errors are not allowed).'
      );
    }
  }

  @override
  Future<IOStreamedResponse> send(http.BaseRequest request) async {
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