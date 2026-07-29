import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

import 'native_endpoint_contract_support.dart';

void main() {
  test('snapshot normalizes query and header order', () {
    final first =
        http.Request('POST', Uri.parse('https://server/v1/test?b=2&a=1'))
          ..headers.addAll({'z-header': 'z', 'a-header': 'a'})
          ..body = '{"x":1}';

    final second =
        http.Request('POST', Uri.parse('https://server/v1/test?a=1&b=2'))
          ..headers.addAll({'a-header': 'a', 'z-header': 'z'})
          ..body = '{"x":1}';

    final firstSnapshot = NativeRequestSnapshot.fromBaseRequest(
      first,
      body: first.body,
    );
    final secondSnapshot = NativeRequestSnapshot.fromBaseRequest(
      second,
      body: second.body,
    );

    expect(firstSnapshot, secondSnapshot);
    expect(firstSnapshot.hashCode, secondSnapshot.hashCode);
    expect(firstSnapshot.query.keys, orderedEquals(['a', 'b']));
    expect(
      firstSnapshot.headers.keys,
      orderedEquals(['a-header', 'content-type', 'z-header']),
    );
  });

  test('snapshot is immutable and preserves exact wire values', () {
    final request =
        http.Request(
            'post',
            Uri.parse(
              'https://server/v1/test?sessionid=SessionValue&appkey=AppKey&empty=',
            ),
          )
          ..headers.addAll({
            'SessionID': 'SessionValue',
            'AppKey': 'AppKey',
            'Content-Type': 'application/json; charset=utf-8',
            'X-Empty': '',
          });

    final snapshot = NativeRequestSnapshot.fromBaseRequest(
      request,
      body: '{"wire":"exact"}',
    );

    expect(snapshot.method, 'POST');
    expect(snapshot.path, '/v1/test');
    expect(snapshot.query, {
      'appkey': 'AppKey',
      'empty': '',
      'sessionid': 'SessionValue',
    });
    expect(snapshot.headers, {
      'appkey': 'AppKey',
      'content-type': 'application/json; charset=utf-8',
      'sessionid': 'SessionValue',
      'x-empty': '',
    });
    expect(snapshot.body, '{"wire":"exact"}');
    expect(() => snapshot.query['other'] = 'value', throwsUnsupportedError);
    expect(() => snapshot.headers['other'] = 'value', throwsUnsupportedError);
  });

  test('contract mismatch names body and both differing values', () {
    final actual = NativeRequestSnapshot(
      method: 'POST',
      path: '/v1/test',
      query: const {},
      headers: const {},
      body: 'actual body value',
    );
    final expected = NativeRequestSnapshot(
      method: 'POST',
      path: '/v1/test',
      query: const {},
      headers: const {},
      body: 'expected body value',
    );
    Object? failure;

    try {
      expectNativeRequestContract(actual, expected);
    } catch (error) {
      failure = error;
    }

    expect(failure, isNotNull);
    expect(
      failure.toString(),
      allOf(
        contains('body differs'),
        contains('actual body value'),
        contains('expected body value'),
      ),
    );
  });
}
