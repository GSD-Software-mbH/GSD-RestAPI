import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/model_response_policy.dart';
import 'package:gsd_restapi/src/runtime/response/response_envelope.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:test/test.dart';

const _operationId = 'test.envelope';

TransportResponse _response(
  String body, {
  int statusCode = 200,
  String? reasonPhrase,
}) {
  return TransportResponse(
    statusCode: statusCode,
    headers: const {'content-type': 'application/json; charset=utf-8'},
    bodyBytes: Uint8List.fromList(utf8.encode(body)),
    body: body,
    reasonPhrase: reasonPhrase,
  );
}

TransportResponse _envelope(
  Object? internalStatus, {
  int statusCode = 200,
  Object? data = const <String, Object?>{},
}) {
  return _response(
    jsonEncode({
      'status': {'internalStatus': internalStatus, 'statusMessage': 'msg'},
      'data': data,
    }),
    statusCode: statusCode,
  );
}

ResponseEnvelope _decode(TransportResponse response) =>
    ResponseEnvelope.decode(response, operationId: _operationId);

void main() {
  group('Regel 1: Status vor data', () {
    final cases = <String, (String, Matcher)>{
      'Data-Policy, 201': ('201', isA<GsdSessionInvalidException>()),
      'Data-Policy, 204': ('204', isA<GsdSessionMissingException>()),
      'Data-Policy, 341': ('341', isA<GsdTwoFactorTokenMissingException>()),
    };
    for (final MapEntry(key: name, value: (status, matcher)) in cases.entries) {
      test('$name wirft die Session-Exception, nicht GsdParseException', () {
        // `data` passt nicht zum erwarteten Typ: Läse die Policy `data`
        // zuerst, käme eine GsdParseException und kein Refresh.
        expect(
          () => const DataResponsePolicy<List<Object?>>().decode(
            _envelope(status, data: 'kein Array'),
            operationId: _operationId,
          ),
          throwsA(matcher),
        );
      });
    }

    test('Model-Policy, 201 wirft vor fromJson', () {
      var fromJsonCalls = 0;
      final policy = ModelResponsePolicy<Object>((json) {
        fromJsonCalls++;
        return json;
      });

      expect(
        () => policy.decode(_envelope('201'), operationId: _operationId),
        throwsA(isA<GsdSessionInvalidException>()),
      );
      expect(fromJsonCalls, 0);
    });
  });

  group('Regel 2: Body ohne JSON-Objekt', () {
    final cases = <String, (TransportResponse, Matcher)>{
      'HTML bei HTTP 502': (
        _response(
          '<html>Bad Gateway</html>',
          statusCode: 502,
          reasonPhrase: 'Bad Gateway',
        ),
        isA<GsdHttpException>()
            .having((e) => e.statusCode, 'statusCode', 502)
            .having((e) => e.reasonPhrase, 'reasonPhrase', 'Bad Gateway'),
      ),
      'leerer Body bei HTTP 200': (
        _response(''),
        isA<GsdParseException>()
            .having((e) => e.operationId, 'operationId', _operationId)
            .having((e) => e.path, 'path', ''),
      ),
      'JSON-Array bei HTTP 200': (
        _response('[1, 2]'),
        isA<GsdParseException>().having((e) => e.path, 'path', ''),
      ),
      'leerer Body bei HTTP 404': (
        _response('', statusCode: 404),
        isA<GsdHttpException>().having((e) => e.statusCode, 'statusCode', 404),
      ),
    };
    for (final MapEntry(key: name, value: (response, matcher))
        in cases.entries) {
      test(name, () {
        expect(() => _decode(response), throwsA(matcher));
      });
    }
  });

  group('Regel 3: JSON ohne status', () {
    for (final statusCode in [200, 500]) {
      test('HTTP $statusCode wirft GsdHttpException', () {
        expect(
          () => _decode(
            _response(
              jsonEncode({'data': <String, Object?>{}}),
              statusCode: statusCode,
              reasonPhrase: 'Reason',
            ),
          ),
          throwsA(
            isA<GsdHttpException>()
                .having((e) => e.statusCode, 'statusCode', statusCode)
                .having((e) => e.reasonPhrase, 'reasonPhrase', 'Reason'),
          ),
        );
      });
    }
  });

  group('Regel 4: internalStatus als int oder String', () {
    for (final status in <Object>['0', 0, 200, '200']) {
      test('${jsonEncode(status)} ist OK', () {
        final envelope = _decode(_envelope(status, data: {'a': 1}));

        expect(envelope.internalStatus, '$status');
        expect(envelope.statusMessage, 'msg');
        expect(envelope.data, {'a': 1});
      });
    }

    test('201 als int wirft GsdSessionInvalidException', () {
      expect(
        () => _decode(_envelope(201)),
        throwsA(
          isA<GsdSessionInvalidException>().having(
            (e) => e.internalStatus,
            'internalStatus',
            '201',
          ),
        ),
      );
    });

    final unreadable = <String, (Object?, String)>{
      'status ist kein Objekt': ('kaputt', 'status'),
      'internalStatus fehlt': (<String, Object?>{}, 'status.internalStatus'),
      'internalStatus ist eine Liste': (
        {
          'internalStatus': [0],
        },
        'status.internalStatus',
      ),
    };
    for (final MapEntry(key: name, value: (status, path))
        in unreadable.entries) {
      test('$name wirft GsdParseException an "$path"', () {
        expect(
          () => _decode(_response(jsonEncode({'status': status}))),
          throwsA(isA<GsdParseException>().having((e) => e.path, 'path', path)),
        );
      });
    }

    test('fehlende statusMessage ergibt einen leeren Text', () {
      final envelope = _decode(
        _response(
          jsonEncode({
            'status': {'internalStatus': '0'},
          }),
        ),
      );

      expect(envelope.statusMessage, isEmpty);
      expect(envelope.data, isNull);
    });
  });

  group('Status-Tabelle', () {
    final table = <String, Matcher>{
      '201': isA<GsdSessionInvalidException>(),
      '204': isA<GsdSessionMissingException>(),
      '302': isA<GsdInvalidCredentialsException>(),
      '306': isA<GsdLicenseException>(),
      '101': isA<GsdLicenseException>(),
      '340': isA<GsdTwoFactorRequiredException>(),
      '341': isA<GsdTwoFactorTokenMissingException>(),
      '342': isA<GsdTwoFactorTokenInvalidException>(),
      '999': isA<GsdServerException>().having(
        (e) => e.runtimeType,
        'runtimeType',
        GsdServerException,
      ),
    };
    for (final MapEntry(key: status, value: matcher) in table.entries) {
      test('$status wirft die passende Exception', () {
        expect(
          () => _decode(_envelope(status)),
          throwsA(
            allOf(
              matcher,
              isA<GsdServerException>()
                  .having((e) => e.internalStatus, 'internalStatus', status)
                  .having((e) => e.statusMessage, 'statusMessage', 'msg'),
            ),
          ),
        );
      });
    }
  });

  group('Regel 5: Umschlag-Status vor HTTP-Status', () {
    test('HTTP 500 mit Umschlag 201 wirft GsdSessionInvalidException', () {
      expect(
        () => _decode(_envelope('201', statusCode: 500)),
        throwsA(isA<GsdSessionInvalidException>()),
      );
    });

    test('HTTP 404 mit Umschlag 0 ist OK', () {
      expect(
        _decode(_envelope('0', statusCode: 404, data: [1])).data,
        [1],
      );
    });
  });

  group('internalStatusOf', () {
    final cases = <String, (Object?, String?)>{
      'String': (
        {
          'status': {'internalStatus': '341'},
        },
        '341',
      ),
      'int': (
        {
          'status': {'internalStatus': 204},
        },
        '204',
      ),
      'ohne status': (<String, Object?>{}, null),
      'kein Objekt': ([1], null),
    };
    for (final MapEntry(key: name, value: (decoded, expected))
        in cases.entries) {
      test(name, () {
        expect(ResponseEnvelope.internalStatusOf(decoded), expected);
      });
    }
  });
}
