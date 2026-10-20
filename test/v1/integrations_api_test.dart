import 'package:flutter_test/flutter_test.dart';

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

  test('postExecuteInterfaceMacro liefert die rohe http.Response', () async {
    harness.enqueueSuccess('POST', '/dfapp/v1/execute/MyMacro');

    final response = await harness.api.v1.integrations
        .postExecuteInterfaceMacro(
          'MyMacro',
          body: <String, dynamic>{'param': 1},
        );

    expect(response.statusCode, 200);
    harness.expectRequest(
      harness.server.requests.single,
      method: 'POST',
      path: '/dfapp/v1/execute/MyMacro',
      body: '{"param":1}',
    );
  });

  test('postExecuteInterfaceMacro ohne Body sendet keinen Body', () async {
    harness.enqueueSuccess('POST', '/dfapp/v1/execute/MyMacro');

    await harness.api.v1.integrations.postExecuteInterfaceMacro('MyMacro');

    expect(harness.server.requests.single.body, '');
  });
}
