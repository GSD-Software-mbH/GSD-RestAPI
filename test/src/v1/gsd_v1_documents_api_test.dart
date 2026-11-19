@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';
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
      const bytes = 'not-json|not-base64';
      harness.server.enqueue(
        'GET',
        '/dfapp/v1/file/file-1',
        (_) => ScriptedResponse(bytes),
      );

      final file = await harness.api.v1.documents.getFile('file-1');

      expect(file.bytes, utf8.encode(bytes));
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
      final bytes = await harness.api.v1.documents.getPreview(
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
      final missing = await harness.api.v1.documents.getPreview(
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
      harness
        ..enqueueSuccess(
          'GET',
          '/dfapp/v1/uploadFile',
          data: <String, dynamic>{'uploadId': 'upload-1'},
        )
        ..enqueueSuccess('POST', '/dfapp/v1/uploadFile/upload-1')
        ..enqueueSuccess(
          'PATCH',
          '/dfapp/v1/uploadFile/upload-1',
          data: <String, dynamic>{'objectId': 'DOC-1'},
        );
      final file = GsdUploadFile.fromBytes(
        name: 'note.txt',
        bytes: Uint8List.fromList(utf8.encode('hello upload')),
      );

      final data = await harness.api.v1.documents.uploadFile(
        file,
        replaceOID: 'replace-1',
      );

      expect(data, <String, dynamic>{'objectId': 'DOC-1'});
      expect(harness.server.requests.map((request) => request.path), <String>[
        '/dfapp/v1/uploadFile',
        '/dfapp/v1/uploadFile/upload-1',
        '/dfapp/v1/uploadFile/upload-1',
      ]);
      final multipart = harness.server.requests[1];
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
      harness
        ..enqueueSuccess(
          'GET',
          '/dfapp/v1/uploadFile',
          data: <String, dynamic>{'uploadId': 'upload-2'},
        )
        ..enqueueSuccess(
          'POST',
          '/dfapp/v1/uploadFile/upload-2',
          data: <String, dynamic>{'step': 'post'},
        );
      final file = GsdUploadFile.fromBytes(
        name: 'note.txt',
        bytes: Uint8List.fromList(<int>[1, 2, 3]),
      );

      final controller = await harness.api.v1.documents
          .uploadFileWithController(file, fetchToObject: false);
      final data = await controller.result;

      expect(controller.uploadId, 'upload-2');
      expect(data, <String, dynamic>{'step': 'post'});
      expect(harness.server.requests, hasLength(2));
    },
  );

  final cases =
      <
        (
          String,
          String,
          String,
          Map<String, String>,
          String,
          Future<Object?> Function(GsdV1DocumentsApi),
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
      harness.enqueueSuccess(method, path, data: <String, Object?>{'ok': true});

      final data = await call(harness.api.v1.documents);

      expect(data, <String, Object?>{'ok': true});
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
    harness.server.fallback = (_) => ScriptedResponse(
      jsonEncode(TestServer.v1Envelope(data: <String, dynamic>{'ok': true})),
    );

    await Future.wait(<Future<Object?>>[
      harness.api.v1.documents.putDocsRead(<String>['doc-1']),
      harness.api.v1.documents.putDocsRead(<String>['doc-1']),
    ]);

    expect(harness.server.requests, hasLength(2));
  });
}
