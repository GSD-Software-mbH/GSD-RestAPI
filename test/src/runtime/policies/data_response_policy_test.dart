import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:test/test.dart';

const _operationId = 'test.data';

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
  group('DataResponsePolicy', () {
    test('liefert eine Liste als List<Object?>', () {
      final data = const DataResponsePolicy<List<Object?>>().decode(
        _ok([
          {'oid': 'A'},
          2,
        ]),
        operationId: _operationId,
      );

      expect(data, [
        {'oid': 'A'},
        2,
      ]);
    });

    test('liefert ein Objekt als Map<String, Object?>', () {
      final data = const DataResponsePolicy<Map<String, Object?>>().decode(
        _ok({'oid': 'A'}),
        operationId: _operationId,
      );

      expect(data, {'oid': 'A'});
    });

    test('Object? nimmt auch null', () {
      expect(
        const DataResponsePolicy<Object?>().decode(
          _ok(null),
          operationId: _operationId,
        ),
        isNull,
      );
    });

    final mismatches = <String, Object? Function(TransportResponse)>{
      'Objekt statt Liste': (response) =>
          const DataResponsePolicy<List<Object?>>().decode(
            response,
            operationId: _operationId,
          ),
      'Liste statt Objekt': (response) =>
          const DataResponsePolicy<Map<String, Object?>>().decode(
            response,
            operationId: _operationId,
          ),
    };
    final payloads = <String, Object?>{
      'Objekt statt Liste': {'oid': 'A'},
      'Liste statt Objekt': [1],
    };
    for (final MapEntry(key: name, value: decode) in mismatches.entries) {
      test('$name wirft GsdParseException an "data"', () {
        expect(
          () => decode(_ok(payloads[name])),
          throwsA(
            isA<GsdParseException>()
                .having((e) => e.operationId, 'operationId', _operationId)
                .having((e) => e.path, 'path', 'data'),
          ),
        );
      });
    }

    test('const-Instanzen sind identisch (Deduplizierung per Identität)', () {
      expect(
        identical(
          const DataResponsePolicy<List<Object?>>(),
          const DataResponsePolicy<List<Object?>>(),
        ),
        isTrue,
      );
    });
  });
}
