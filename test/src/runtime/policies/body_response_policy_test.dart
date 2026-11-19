import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/policies/body_response_policy.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:test/test.dart';

const _operationId = 'test.body';

TransportResponse _response(Map<String, Object?> json) {
  final body = jsonEncode(json);
  return TransportResponse(
    statusCode: 200,
    headers: const {},
    bodyBytes: Uint8List.fromList(utf8.encode(body)),
    body: body,
  );
}

void main() {
  group('BodyResponsePolicy', () {
    test('liefert den ganzen Body samt Schlüsseln neben data', () {
      final json = {
        'status': {'internalStatus': '0', 'statusMessage': 'OK'},
        'objectId': '100,200,1',
        'object': {'Name': 'Test'},
        'data': {'clientDirective': null},
      };

      expect(
        const BodyResponsePolicy().decode(
          _response(json),
          operationId: _operationId,
        ),
        json,
      );
    });

    test('wertet zuerst den Status aus', () {
      expect(
        () => const BodyResponsePolicy().decode(
          _response({
            'status': {'internalStatus': '201', 'statusMessage': 'expired'},
          }),
          operationId: _operationId,
        ),
        throwsA(isA<GsdSessionInvalidException>()),
      );
    });
  });
}
