// V3-Endpunkt-Tests für `api.v3.file` und `/v3/`-Pfade.
//
// Die Tests laufen gegen den lokalen Mock-Server und prüfen den
// Client-Vertrag (Pfad, Verb, Query, kein v1/multi).

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import '../legacy/legacy_test_server.dart';
import 'v3_test_support.dart';

void main() {
  late V3TestHarness harness;

  setUp(() async {
    harness = await V3TestHarness.start();
  });

  tearDown(() => harness.close());

  test('file.get ohne Zusatzparameter sendet nur v3/file/{oid}', () async {
    const String bytes = 'not-json|not-base64';
    harness.server.enqueue(
      'GET',
      '/dfapp/v3/file/1PTF',
      (_) => ScriptedResponse(bytes),
    );

    final RestApiFileResponse response = await harness.api.v3.file.get('1PTF');

    expect(response.isOk, isTrue);
    expect(response.httpResponse.bodyBytes, utf8.encode(bytes));
    harness.expectSingleRequest(method: 'GET', path: '/dfapp/v3/file/1PTF');
  });

  test('file.get hängt page als Query-Parameter an', () async {
    harness.server.enqueue(
      'GET',
      '/dfapp/v3/file/1PTF',
      (_) => ScriptedResponse('page-3-bytes'),
    );

    final RestApiFileResponse response = await harness.api.v3.file.get(
      '1PTF',
      page: 3,
    );

    expect(response.isOk, isTrue);
    final RecordedRequest request = harness.server.requests.single;
    expect(request.method, 'GET');
    expect(request.path, '/dfapp/v3/file/1PTF');
    expect(request.query, <String, String>{'page': '3'});
  });

  test('file.get sendet alle Zusatzparameter, wenn gesetzt', () async {
    harness.server.enqueue(
      'GET',
      '/dfapp/v3/file/mail-oid',
      (_) => ScriptedResponse('attachment-bytes'),
    );

    await harness.api.v3.file.get(
      'mail-oid',
      page: 1,
      usePdf: true,
      attachItem: 3,
      zipItem: 2,
      maxSize: 512,
    );

    expect(harness.server.requests.single.query, <String, String>{
      'page': '1',
      'usePdf': 'true',
      'attachItem': '3',
      'zipItem': '2',
      'maxSize': '512',
    });
  });

  test(
    'file.get sendet usePdf=false explizit, aber nie null-Parameter',
    () async {
      harness.server.enqueue(
        'GET',
        '/dfapp/v3/file/1PTF',
        (_) => ScriptedResponse('original-bytes'),
      );

      await harness.api.v3.file.get('1PTF', usePdf: false);

      expect(harness.server.requests.single.query, <String, String>{
        'usePdf': 'false',
      });
    },
  );

  test('file.get läuft direkt und nie über v1/multi', () async {
    harness.server.enqueue(
      'GET',
      '/dfapp/v3/file/1PTF',
      (_) => ScriptedResponse('direct-bytes'),
    );

    await harness.api.v3.file.get('1PTF', page: 3);

    expect(
      harness.server.requests.where(
        (entry) => entry.path.endsWith('/v1/multi'),
      ),
      isEmpty,
    );
  });

  test('file.get wirft bei Statuscode != 200', () async {
    harness.server.enqueue(
      'GET',
      '/dfapp/v3/file/missing',
      (_) => ScriptedResponse('not found', statusCode: 404),
    );

    await expectLater(
      harness.api.v3.file.get('missing'),
      throwsA(isA<HttpRequestException>()),
    );
  });
}
