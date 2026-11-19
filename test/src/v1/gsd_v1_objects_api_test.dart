@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';
import 'v1_test_support.dart';

void main() {
  late V1TestHarness native;

  setUp(() async {
    native = await V1TestHarness.start();

    ScriptedResponse success(RecordedRequest _) => ScriptedResponse(
      jsonEncode(
        TestServer.v1Envelope(
          data: <String, dynamic>{'isLocked': false, 'messages': <String>[]},
        ),
      ),
    );
    native.server.fallback = success;
  });

  tearDown(() async {
    await native.close();
  });

  final cases = <(String, Future<void> Function(GsdV1ObjectsApi))>[
    (
      'getObject',
      (api) async {
        await api.getObject(
          'object-1',
          className: 'Vorgang',
          serialization: '{"mode":"full"}',
        );
      },
    ),
    (
      'postObject',
      (api) async {
        await api.postObject(
          'Vorgang',
          '{"name":"Neu"}',
          storeMode: 10,
          serialization: '{"mode":"full"}',
          actions: '[{"type":"notify"}]',
          rightsControlKey: 'rights-1',
        );
      },
    ),
    (
      'patchObject',
      (api) async {
        await api.patchObject(
          'object-1',
          '{"name":"Geändert"}',
          storeMode: 10,
          storeSecurityPolice: 20,
          serialization: '{"mode":"full"}',
          actions: '[{"type":"notify"}]',
          rightsControlKey: 'rights-1',
        );
      },
    ),
    (
      'deleteObject',
      (api) async {
        await api.deleteObject(
          'object-1',
          actions: '[{"type":"notify"}]',
          moveToRecycler: true,
        );
      },
    ),
    (
      'getObjects',
      (api) async {
        await api.getObjects(
          'Vorgang',
          query: 'status:open',
          page: 2,
          perPage: 25,
          serialization: '{"mode":"list"}',
          actions: '[{"type":"preview"}]',
          rightsControlKey: 'rights-1',
        );
      },
    ),
    (
      'patchObjects',
      (api) async {
        await api.patchObjects(
          'Vorgang',
          query: 'status:open',
          body: '{"status":"closed"}',
          storeMode: 10,
          storeSecurityPolice: 20,
          serialization: '{"mode":"list"}',
          actions: '[{"type":"notify"}]',
          rightsControlKey: 'rights-1',
        );
      },
    ),
    (
      'postAction',
      (api) async {
        await api.postAction(
          'Vorgang',
          query: '{"oids":["object-1"]}',
          page: 3,
          perPage: 10,
          serialization: '{"mode":"full"}',
          actions: '[{"type":"sendObject"}]',
          rightsControlKey: 'rights-1',
        );
      },
    ),
    (
      'getLockObject',
      (api) async {
        await api.getLockObject('object-1');
      },
    ),
    (
      'getIncidentTree',
      (api) async {
        await api.getIncidentTree(
          'incident-1',
          deepLevel: 3,
          serialization: '{"children":true}',
          rightsControlKey: 'rights-1',
        );
      },
    ),
    (
      'setObjectSecurity',
      (api) async {
        await api.setObjectSecurity('object-1', <String, int>{
          'alice': 7,
          'bob': 15,
        }, replace: true);
      },
    ),
  ];

  for (final (name, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callNative(native.api.v1.objects);

      expect(native.server.requests, hasLength(1));
      native.expectLegacyWire('objects.$name', native.server.requests.single);
    });
  }

  test('Listen-Endpunkte übernehmen den perPage-Config-Default', () async {
    await native.api.v1.objects.getObjects('Vorgang');
    await native.api.v1.objects.postAction('Vorgang');

    expect(native.server.requests, hasLength(2));
    for (final request in native.server.requests) {
      expect(request.query, const <String, String>{'perPage': '50'});
    }
  });

  test('getLockObject liefert den bestehenden typisierten Response', () async {
    native.server.enqueueJson(
      'GET',
      '/dfapp/v1/lock/object/object-1',
      body: TestServer.v1Envelope(
        data: <String, dynamic>{
          'isLocked': true,
          'messages': <String>['Gesperrt durch Demo'],
        },
      ),
    );

    final response = await native.api.v1.objects.getLockObject('object-1');

    expect(response.isLocked, isTrue);
    expect(response.messages, <String>['Gesperrt durch Demo']);
  });

  test(
    'setObjectSecurity lässt replace=false wie Legacy aus dem Body',
    () async {
      await native.api.v1.objects.setObjectSecurity('object-1', <String, int>{
        'alice': 7,
      });

      expect(jsonDecode(native.server.requests.single.body), <String, dynamic>{
        'security': <Map<String, dynamic>>[
          <String, dynamic>{'userObjectName': 'alice', 'rights': 7},
        ],
      });
    },
  );

  test(
    'zehn unterschiedliche getObjects-Aufrufe werden als ein v1/multi gesendet',
    () async {
      final multi = await V1TestHarness.start(multiRequest: true);
      addTearDown(multi.close);

      multi.server.enqueue('POST', '/dfapp/v1/multi', (request) {
        final items = jsonDecode(request.body) as List<dynamic>;
        final results = List<Map<String, dynamic>>.generate(
          items.length,
          (index) => <String, dynamic>{
            'httpStatus': 200,
            'result': TestServer.v1Envelope(
              data: <String, dynamic>{'~Count': index},
            ),
          },
        );
        return ScriptedResponse(
          jsonEncode(TestServer.v1Envelope(data: results)),
        );
      });

      final responses = await Future.wait(
        List<Future<Object?>>.generate(
          10,
          (index) => multi.api.v1.objects.getObjects('Dokument', page: index),
        ),
      );

      expect(multi.server.requests, hasLength(1));
      final request = multi.server.requests.single;
      expect(request.method, 'POST');
      expect(request.path, '/dfapp/v1/multi');
      expect(request.header('sessionid'), V1TestHarness.sessionId);

      final items = jsonDecode(request.body) as List<dynamic>;
      expect(items, hasLength(10));
      for (var index = 0; index < items.length; index++) {
        final item = items[index] as Map<String, dynamic>;
        expect(item['method'], 'GET');
        expect(
          item['path'],
          index == 0
              ? '/v1/objects/Dokument?perPage=50'
              : '/v1/objects/Dokument?page=$index&perPage=50',
        );
        expect(item, isNot(contains('data')));
      }

      expect(responses, hasLength(10));
      for (var index = 0; index < responses.length; index++) {
        expect(responses[index], <String, dynamic>{'~Count': index});
      }
    },
  );
}
