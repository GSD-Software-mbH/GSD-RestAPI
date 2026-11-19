import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/src/runtime/response/recoverable_session_status.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:test/test.dart';

TransportResponse _response(String body, {int statusCode = 200}) {
  return TransportResponse(
    statusCode: statusCode,
    headers: const {},
    bodyBytes: Uint8List.fromList(utf8.encode(body)),
    body: body,
  );
}

Map<String, Object?> _envelope(Object? internalStatus) => {
  'status': {'internalStatus': internalStatus, 'statusMessage': 'msg'},
};

void main() {
  group('RecoverableSessionStatus.of', () {
    final cases = <String, (TransportResponse, String?)>{
      '201 als String': (_response(jsonEncode(_envelope('201'))), '201'),
      '204 als int': (_response(jsonEncode(_envelope(204))), '204'),
      '341 als String': (_response(jsonEncode(_envelope('341'))), '341'),
      '201 bei HTTP 500': (
        _response(jsonEncode(_envelope('201')), statusCode: 500),
        '201',
      ),
      'OK-Status 0': (_response(jsonEncode(_envelope('0'))), null),
      'OK-Status 200': (_response(jsonEncode(_envelope(200))), null),
      '302 (falsche Zugangsdaten)': (
        _response(jsonEncode(_envelope('302'))),
        null,
      ),
      '340 (2FA erforderlich)': (_response(jsonEncode(_envelope('340'))), null),
      '342 (2FA-Token ungültig)': (
        _response(jsonEncode(_envelope('342'))),
        null,
      ),
      '999 (Serverfehler)': (_response(jsonEncode(_envelope('999'))), null),
      'Body ist kein JSON': (_response('<html>201</html>'), null),
      'leerer Body': (_response(''), null),
      'JSON-Array': (_response('["201"]'), null),
      'JSON ohne status': (
        _response(jsonEncode({'internalStatus': '201'})),
        null,
      ),
      'status ohne internalStatus': (
        _response(
          jsonEncode({
            'status': {'statusMessage': '201'},
          }),
        ),
        null,
      ),
      'internalStatus als Liste': (
        _response(
          jsonEncode(
            _envelope(['201']),
          ),
        ),
        null,
      ),
    };
    for (final MapEntry(key: name, value: (response, expected))
        in cases.entries) {
      test('$name ergibt ${expected ?? 'null'}', () {
        expect(RecoverableSessionStatus.of(response), expected);
      });
    }
  });

  group('RecoverableSessionStatus.fromEnvelope', () {
    final cases = <String, (Object?, String?)>{
      'null': (null, null),
      'String': ('201', null),
      'Map mit 341 als int': (_envelope(341), '341'),
      'Map mit 204 als String': (_envelope('204'), '204'),
      'Map mit 0': (_envelope(0), null),
      'status ist kein Objekt': (<String, Object?>{'status': '201'}, null),
    };
    for (final MapEntry(key: name, value: (decoded, expected))
        in cases.entries) {
      test('$name ergibt ${expected ?? 'null'}', () {
        expect(RecoverableSessionStatus.fromEnvelope(decoded), expected);
      });
    }
  });
}
