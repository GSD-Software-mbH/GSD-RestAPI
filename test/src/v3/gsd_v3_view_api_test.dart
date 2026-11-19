@TestOn('vm')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
// V3-Endpunkt-Tests für `api.v3.view` und `/v3/`-Pfade.
//
// Die Tests laufen gegen den lokalen Mock-Server und prüfen den
// Client-Vertrag (Pfad, Verb, Body, Rückgabe, kein v1/multi).

import 'package:test/test.dart';

import '../../helpers/test_server.dart';
import 'v3_test_support.dart';

void main() {
  late V3TestHarness harness;

  setUp(() async {
    harness = await V3TestHarness.start();
  });

  tearDown(() => harness.close());

  test('view.load übernimmt den DOCUframe-App-Body', () async {
    final data = [
      {
        'view': {'name': 'edit'},
      },
      null,
    ];
    harness.enqueueData('POST', '/dfapp/v3/view/load', data);

    final views = await harness.api.v3.view.load([
      const GsdViewLoadRequest(
        viewName: 'edit',
        className: 'Dokument',
        context: 'mobile',
      ),
      const GsdViewLoadRequest(viewName: 'theme'),
    ]);

    expect(views, data);
    harness.expectSingleRequest(
      method: 'POST',
      path: '/dfapp/v3/view/load',
      body: loadV3Fixture('view_load_request.json'),
    );
  });

  test('view.action übernimmt den DOCUframe-App-Body', () async {
    final response = {
      ...TestServer.v1Envelope(
        data: {
          'clientDirective': {'refresh': true},
        },
      ),
      'objectId': '100,200,1',
      'object': {'Name': 'Neu'},
    };
    harness.server.enqueueJson(
      'POST',
      '/dfapp/v3/view/action',
      body: response,
    );

    final body = await harness.api.v3.view.action(
      const GsdViewActionRequest(
        actionOid: '4TOF',
        tryCount: 0,
        payload: {
          '~StoreTime': '20260910T104512+02:00',
          'viewOpenTime': '20260910T104123+02:00',
          'forms': {
            'editnote': {
              'HC12': {
                '~ClassName': 'Notiz',
                'Name': {'old': 'Alt', 'new': 'Neu'},
              },
            },
          },
          'data': {'folder': 'HA3G'},
        },
      ),
    );

    expect(body, response);
    harness.expectSingleRequest(
      method: 'POST',
      path: '/dfapp/v3/view/action',
      body: loadV3Fixture('view_action_request.json'),
    );
  });
}
