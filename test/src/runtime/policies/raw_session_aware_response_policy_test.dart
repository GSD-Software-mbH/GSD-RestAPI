import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/policies/raw_session_aware_response_policy.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:test/test.dart';

const _operationId = 'test.raw';

TransportResponse _response(
  String body, {
  int statusCode = 200,
  Map<String, String> headers = const {'content-type': 'application/json'},
}) {
  return TransportResponse(
    statusCode: statusCode,
    headers: headers,
    bodyBytes: Uint8List.fromList(utf8.encode(body)),
    body: body,
  );
}

String _envelope(Object? internalStatus) => jsonEncode({
  'status': {'internalStatus': internalStatus, 'statusMessage': 'msg'},
  'data': {'value': 1},
});

GsdRawApiResponse _decode(TransportResponse response) =>
    const RawSessionAwareResponsePolicy().decode(
      response,
      operationId: _operationId,
    );

void main() {
  group('RawSessionAwareResponsePolicy: recoverbare Sessionstatus', () {
    final cases = <String, (TransportResponse, Matcher)>{
      '201': (_response(_envelope('201')), isA<GsdSessionInvalidException>()),
      '201 als int': (
        _response(_envelope(201)),
        isA<GsdSessionInvalidException>(),
      ),
      '204': (_response(_envelope('204')), isA<GsdSessionMissingException>()),
      '341': (
        _response(_envelope('341')),
        isA<GsdTwoFactorTokenMissingException>(),
      ),
      '201 bei HTTP 500': (
        _response(_envelope('201'), statusCode: 500),
        isA<GsdSessionInvalidException>(),
      ),
    };
    for (final MapEntry(key: name, value: (response, matcher))
        in cases.entries) {
      test('$name wirft die Session-Exception', () {
        expect(
          () => _decode(response),
          throwsA(
            allOf(
              matcher,
              isA<GsdServerException>().having(
                (e) => e.statusMessage,
                'statusMessage',
                'msg',
              ),
            ),
          ),
        );
      });
    }
  });

  group('RawSessionAwareResponsePolicy: reicht alles andere raw durch', () {
    final cases = <String, TransportResponse>{
      'OK-Envelope 0': _response(_envelope('0')),
      'internalStatus 302': _response(_envelope('302')),
      'internalStatus 340': _response(_envelope('340')),
      'internalStatus 342': _response(_envelope('342')),
      'internalStatus 999 bei HTTP 500': _response(
        _envelope('999'),
        statusCode: 500,
      ),
      'HTTP 404 ohne Body': _response('', statusCode: 404),
      'HTTP 502 mit HTML': _response(
        '<html>Bad Gateway</html>',
        statusCode: 502,
        headers: const {'content-type': 'text/html'},
      ),
      'Klartext bei HTTP 200': _response(
        'kein JSON',
        headers: const {'content-type': 'text/plain'},
      ),
      'JSON-Array': _response('[201, 204, 341]'),
      'JSON ohne status': _response(jsonEncode({'data': 'x'})),
    };
    for (final MapEntry(key: name, value: response) in cases.entries) {
      test(name, () {
        final raw = _decode(response);

        expect(raw.statusCode, response.statusCode);
        expect(raw.body, response.body);
        expect(raw.bodyBytes, response.bodyBytes);
        expect(raw.headers, response.headers);
      });
    }

    test('die Header der Raw-Antwort sind unveränderlich', () {
      final raw = _decode(_response(_envelope('0')));

      expect(() => raw.headers['x'] = 'y', throwsUnsupportedError);
    });
  });
}
