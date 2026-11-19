import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/policies/binary_response_policy.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:test/test.dart';

const _operationId = 'test.file';

TransportResponse _response(
  String body, {
  int statusCode = 200,
  Map<String, String> headers = const {},
  String? reasonPhrase,
}) => TransportResponse(
  statusCode: statusCode,
  headers: headers,
  bodyBytes: Uint8List.fromList(utf8.encode(body)),
  body: body,
  reasonPhrase: reasonPhrase,
);

void main() {
  group('FileDownloadResponsePolicy', () {
    test('liefert Bytes und Header unverändert, auch ohne Umschlag', () {
      final download = const FileDownloadResponsePolicy().decode(
        _response(
          'not-json|not-base64',
          headers: {
            'content-type': 'application/pdf',
            'content-disposition': 'attachment; filename="a.pdf"',
          },
        ),
        operationId: _operationId,
      );

      expect(download.bytes, utf8.encode('not-json|not-base64'));
      expect(download.headers, {
        'content-type': 'application/pdf',
        'content-disposition': 'attachment; filename="a.pdf"',
      });
    });

    test('wirft bei HTTP-Status ungleich 200 GsdHttpException', () {
      expect(
        () => const FileDownloadResponsePolicy().decode(
          _response('', statusCode: 404, reasonPhrase: 'Not Found'),
          operationId: _operationId,
        ),
        throwsA(
          isA<GsdHttpException>()
              .having((e) => e.statusCode, 'statusCode', 404)
              .having((e) => e.reasonPhrase, 'reasonPhrase', 'Not Found'),
        ),
      );
    });

    test('ist eine IBinaryResponsePolicy, umgeht also die Entschlüsselung', () {
      expect(
        const FileDownloadResponsePolicy(),
        isA<IBinaryResponsePolicy<GsdFileDownload>>(),
      );
    });
  });
}
