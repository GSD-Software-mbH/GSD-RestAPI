import 'dart:collection';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

final class NativeRequestSnapshot {
  final String method;
  final String path;
  final Map<String, String> query;
  final Map<String, String> headers;
  final String? body;

  NativeRequestSnapshot({
    required this.method,
    required this.path,
    required Map<String, String> query,
    required Map<String, String> headers,
    required this.body,
  }) : query = Map.unmodifiable(SplayTreeMap.of(query)),
       headers = Map.unmodifiable(
         SplayTreeMap.of(
           headers.map((name, value) => MapEntry(name.toLowerCase(), value)),
         ),
       );

  factory NativeRequestSnapshot.fromBaseRequest(
    http.BaseRequest request, {
    String? body,
  }) {
    return NativeRequestSnapshot(
      method: request.method.toUpperCase(),
      path: request.url.path,
      query: request.url.queryParameters,
      headers: request.headers,
      body: body,
    );
  }

  static bool _mapEquals(Map<String, String> left, Map<String, String> right) {
    if (left.length != right.length) return false;
    return left.entries.every((entry) => right[entry.key] == entry.value);
  }

  @override
  bool operator ==(Object other) {
    return other is NativeRequestSnapshot &&
        method == other.method &&
        path == other.path &&
        _mapEquals(query, other.query) &&
        _mapEquals(headers, other.headers) &&
        body == other.body;
  }

  @override
  int get hashCode => Object.hash(
    method,
    path,
    Object.hashAll(query.entries.map((e) => Object.hash(e.key, e.value))),
    Object.hashAll(headers.entries.map((e) => Object.hash(e.key, e.value))),
    body,
  );

  @override
  String toString() =>
      'NativeRequestSnapshot('
      'method: $method, path: $path, query: $query, '
      'headers: $headers, body: $body)';
}

void expectNativeRequestContract(
  NativeRequestSnapshot actual,
  NativeRequestSnapshot expected,
) {
  expect(actual.method, expected.method, reason: 'method differs');
  expect(actual.path, expected.path, reason: 'path differs');
  expect(actual.query, expected.query, reason: 'query differs');
  expect(actual.headers, expected.headers, reason: 'headers differ');
  expect(actual.body, expected.body, reason: 'body differs');
}
