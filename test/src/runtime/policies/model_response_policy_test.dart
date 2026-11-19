import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/policies/model_response_policy.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:json_annotation/json_annotation.dart';
import 'package:test/test.dart';

const _operationId = 'test.model';

/// Modell wie aus `json_serializable` mit `checked: true`: Fehler kommen als
/// [CheckedFromJsonException] mit dem Schlüssel.
class _Session {
  const _Session(this.sessionId);

  factory _Session.fromJson(Map<String, Object?> json) {
    final sessionId = json['sessionId'];
    if (sessionId is! String) {
      throw CheckedFromJsonException(
        json,
        'sessionId',
        '_Session',
        'sessionId fehlt',
      );
    }
    return _Session(sessionId);
  }

  final String sessionId;
}

TransportResponse _ok(Object? data) {
  final body = jsonEncode({
    'status': {'internalStatus': '0', 'statusMessage': 'OK'},
    'data': data,
  });
  return TransportResponse(
    statusCode: 200,
    headers: const {},
    bodyBytes: Uint8List.fromList(utf8.encode(body)),
    body: body,
  );
}

void main() {
  const policy = ModelResponsePolicy<_Session>(_Session.fromJson);

  group('ModelResponsePolicy', () {
    test('baut das Modell aus data', () {
      final session = policy.decode(
        _ok({'sessionId': 'S1'}),
        operationId: _operationId,
      );

      expect(session.sessionId, 'S1');
    });

    test('CheckedFromJsonException wird GsdParseException mit dem Schlüssel '
        'als path', () {
      expect(
        () => policy.decode(
          _ok({'sessionId': 42, 'secret': 'geheim'}),
          operationId: _operationId,
        ),
        throwsA(
          isA<GsdParseException>()
              .having((e) => e.operationId, 'operationId', _operationId)
              .having((e) => e.path, 'path', 'data.sessionId')
              .having((e) => '$e', 'toString', isNot(contains('geheim'))),
        ),
      );
    });

    test('CheckedFromJsonException ohne Schlüssel ergibt path "data"', () {
      final withoutKey = ModelResponsePolicy<_Session>(
        (json) => throw CheckedFromJsonException(json, null, '_Session', 'x'),
      );

      expect(
        () => withoutKey.decode(_ok(<String, Object?>{}), operationId: 'op'),
        throwsA(isA<GsdParseException>().having((e) => e.path, 'path', 'data')),
      );
    });

    for (final data in <Object?>[null, 'text', <Object?>[]]) {
      test('data ${jsonEncode(data)} ist kein Objekt: GsdParseException', () {
        expect(
          () => policy.decode(_ok(data), operationId: _operationId),
          throwsA(
            isA<GsdParseException>().having((e) => e.path, 'path', 'data'),
          ),
        );
      });
    }
  });
}
