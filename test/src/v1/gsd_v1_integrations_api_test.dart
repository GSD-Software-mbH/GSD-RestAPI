@TestOn('vm')
library;

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

  test('getCalls sendet Listenparameter inkl. perPage-Default', () async {
    harness.enqueueSuccess(
      'GET',
      '/dfapp/v1/calls',
      data: <String, dynamic>{'calls': <dynamic>[]},
    );

    await harness.api.v1.integrations.getCalls(
      query: 'foo',
      page: 2,
      serialization: '{"type":"class"}',
      rightsControlKey: 'rck',
    );

    final request = harness.server.requests.single;
    expect(request.method, 'GET');
    expect(request.path, '/dfapp/v1/calls');
    expect(request.query, <String, String>{
      'query': 'foo',
      'page': '2',
      'perPage': '50',
      'serialization': '{"type":"class"}',
      'rightsControlKey': 'rck',
    });
  });

  test('getCalls lässt page bei 0 weg, sendet perPage aber immer', () async {
    harness.enqueueSuccess('GET', '/dfapp/v1/calls');

    await harness.api.v1.integrations.getCalls();

    expect(harness.server.requests.single.query, <String, String>{
      'perPage': '50',
    });
  });

  test('postPrintMacrosExecute baut den optionalen Body auf', () async {
    harness.enqueueSuccess('POST', '/dfapp/v1/printMacros/execute');

    await harness.api.v1.integrations.postPrintMacrosExecute(
      'Vorlage',
      addressOid: 'addr-1',
      incidentOid: 'inc-1',
    );

    harness.expectRequest(
      harness.server.requests.single,
      method: 'POST',
      path: '/dfapp/v1/printMacros/execute',
      body: '{"text":"Vorlage","address":"addr-1","incident":"inc-1"}',
    );
  });

  test('postExecuteInterfaceMacro liefert data der Antwort', () async {
    harness.enqueueSuccess(
      'POST',
      '/dfapp/v1/execute/MyMacro',
      data: <String, dynamic>{'result': 1},
    );

    final data = await harness.api.v1.integrations.postExecuteInterfaceMacro(
      'MyMacro',
      body: <String, dynamic>{'param': 1},
    );

    expect(data, <String, dynamic>{'result': 1});
    harness.expectRequest(
      harness.server.requests.single,
      method: 'POST',
      path: '/dfapp/v1/execute/MyMacro',
      body: '{"param":1}',
    );
  });

  test('postExecuteInterfaceMacro wertet den Status aus', () async {
    // Bis 0.2.x kam die Antwort ungeprüft zurück; jetzt wirft ein
    // Fehlerstatus wie bei jedem anderen Endpunkt.
    harness.server.enqueueJson(
      'POST',
      '/dfapp/v1/execute/MyMacro',
      body: TestServer.v1Envelope(
        internalStatus: '500',
        statusMessage: 'macro failed',
      ),
    );

    await expectLater(
      harness.api.v1.integrations.postExecuteInterfaceMacro('MyMacro'),
      throwsA(
        isA<GsdServerException>().having(
          (e) => e.internalStatus,
          'internalStatus',
          '500',
        ),
      ),
    );
  });

  test('postExecuteInterfaceMacro ohne Body sendet keinen Body', () async {
    harness.enqueueSuccess('POST', '/dfapp/v1/execute/MyMacro');

    await harness.api.v1.integrations.postExecuteInterfaceMacro('MyMacro');

    expect(harness.server.requests.single.body, '');
  });
}
