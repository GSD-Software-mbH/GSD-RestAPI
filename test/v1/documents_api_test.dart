// ignore_for_file: deprecated_member_use_from_same_package

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import '../legacy/legacy_test_server.dart';
import 'v1_test_support.dart';

void main() {
  late V1TestHarness harness;

  setUp(() async {
    harness = await V1TestHarness.start();
  });

  tearDown(() => harness.close());

  test(
    'getFile bewahrt Nicht-JSON-Binärbytes und umgeht Entschlüsselung',
    () async {
      const String bytes = 'not-json|not-base64';
      harness.server.enqueue(
        'GET',
        '/dfapp/v1/file/file-1',
        (_) => ScriptedResponse(bytes),
      );

      final RestApiFileResponse response = await harness.api.v1.documents
          .getFile('file-1');

      expect(response.isOk, isTrue);
      expect(response.httpResponse.bodyBytes, utf8.encode(bytes));
      expect(harness.server.requests.single.header('sessionid'), 'V1-SESSION');
    },
  );

  test(
    'getPreview bewahrt beide Legacy-Pfade und liefert non-200 als null',
    () async {
      harness.server.enqueue(
        'GET',
        '/dfapp/v1/preview/200x100/keep-ratio/object-1/2',
        (_) => ScriptedResponse('preview|bytes'),
      );
      final Uint8List? bytes = await harness.api.v1.documents.getPreview(
        'object-1',
        '200x100',
        page: 2,
      );
      expect(bytes, utf8.encode('preview|bytes'));

      harness.server.enqueue(
        'GET',
        '/dfapp/v1/preview/200x100//object-1/0',
        (_) => ScriptedResponse('missing', statusCode: 404),
      );
      final Uint8List? missing = await harness.api.v1.documents.getPreview(
        'object-1',
        '200x100',
        keepRatio: false,
      );
      expect(missing, isNull);
    },
  );

  test(
    'Upload-Fassade verwendet den angebundenen Executor und exaktes Multipart',
    () async {
      harness.enqueueSuccess(
        'GET',
        '/dfapp/v1/uploadFile',
        data: <String, dynamic>{'uploadId': 'upload-1'},
      );
      harness.enqueueSuccess('POST', '/dfapp/v1/uploadFile/upload-1');
      harness.enqueueSuccess('PATCH', '/dfapp/v1/uploadFile/upload-1');
      final RestApiUploadFile file = RestApiUploadFile.fromBytes(
        name: 'note.txt',
        bytes: Uint8List.fromList(utf8.encode('hello upload')),
      );

      final RestApiResponse response = await harness.api.v1.documents
          .uploadFile(file, replaceOID: 'replace-1', patch: false);

      expect(response.isOk, isTrue);
      expect(harness.server.requests.map((request) => request.path), <String>[
        '/dfapp/v1/uploadFile',
        '/dfapp/v1/uploadFile/upload-1',
        '/dfapp/v1/uploadFile/upload-1',
      ]);
      final RecordedRequest multipart = harness.server.requests[1];
      expect(multipart.method, 'POST');
      expect(
        multipart.header('content-type'),
        startsWith('multipart/form-data;'),
      );
      expect(multipart.body, contains('filename="note.txt"'));
      expect(multipart.body, contains('hello upload'));
      expect(harness.server.requests[2].query, const <String, String>{
        'replaceOID': 'replace-1',
      });
    },
  );

  test(
    'Controller-Upload liefert bei fetchToObject:false die POST-Antwort',
    () async {
      harness.enqueueSuccess(
        'GET',
        '/dfapp/v1/uploadFile',
        data: <String, dynamic>{'uploadId': 'upload-2'},
      );
      harness.enqueueSuccess(
        'POST',
        '/dfapp/v1/uploadFile/upload-2',
        data: <String, dynamic>{'step': 'post'},
      );
      final RestApiUploadFile file = RestApiUploadFile.fromBytes(
        name: 'note.txt',
        bytes: Uint8List.fromList(<int>[1, 2, 3]),
      );

      final RestAPIFileUploadController controller = await harness
          .api
          .v1
          .documents
          .uploadFileWithController(file, fetchToObject: false, out: Object());
      final RestApiResponse response = await controller.result;

      expect(controller.uploadId, 'upload-2');
      expect(jsonDecode(response.httpResponse.body)['data'], <String, dynamic>{
        'step': 'post',
      });
      expect(harness.server.requests, hasLength(2));
    },
  );

  final List<
    (
      String,
      String,
      String,
      Map<String, String>,
      String,
      Future<RestApiResponse> Function(V1DocumentsApi),
    )
  >
  cases =
      <
        (
          String,
          String,
          String,
          Map<String, String>,
          String,
          Future<RestApiResponse> Function(V1DocumentsApi),
        )
      >[
        (
          'getUploadFile',
          'GET',
          '/dfapp/v1/uploadFile/upload-3',
          const <String, String>{},
          '',
          (api) => api.getUploadFile('upload-3'),
        ),
        (
          'putDocsRead',
          'PUT',
          '/dfapp/v1/docs/read',
          const <String, String>{},
          '{"read":false,"ids":["doc-1"]}',
          (api) => api.putDocsRead(<String>['doc-1'], read: false),
        ),
        (
          'putDocsNotNew',
          'PUT',
          '/dfapp/v1/docs/removeDocFromNewDocuments',
          const <String, String>{},
          '{"ids":["doc-1"]}',
          (api) => api.putDocsNotNew(<String>['doc-1']),
        ),
        (
          'putDocsHistory',
          'PUT',
          '/dfapp/v1/docs/history',
          const <String, String>{},
          '{"action":"remove","ids":["doc-1"],"className":"Dokument"}',
          (api) => api.putDocsHistory(
            <String>['doc-1'],
            action: 'remove',
            className: 'Dokument',
          ),
        ),
        (
          'getDocumentPaths',
          'GET',
          '/dfapp/v1/docs/documentPaths/doc-1',
          const <String, String>{'extended': 'false'},
          '',
          (api) => api.getDocumentPaths('doc-1'),
        ),
      ];

  for (final (name, method, path, query, body, call) in cases) {
    test('$name bewahrt den Legacy-Wire-Vertrag', () async {
      harness.enqueueSuccess(method, path);

      final RestApiResponse response = await call(harness.api.v1.documents);

      expect(response.isOk, isTrue);
      harness.expectRequest(
        harness.server.requests.single,
        method: method,
        path: path,
        query: query,
        body: body,
      );
    });
  }

  test('identische schreibende Aufrufe werden nicht dedupliziert', () async {
    harness.server.fallback = (RecordedRequest _) => ScriptedResponse(
      jsonEncode(v1Envelope(data: <String, dynamic>{'ok': true})),
    );

    await Future.wait(<Future<RestApiResponse>>[
      harness.api.v1.documents.putDocsRead(<String>['doc-1']),
      harness.api.v1.documents.putDocsRead(<String>['doc-1']),
    ]);

    expect(harness.server.requests, hasLength(2));
  });
}
