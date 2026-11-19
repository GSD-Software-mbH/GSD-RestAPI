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
      jsonEncode(TestServer.v1Envelope(data: <String, dynamic>{'ok': true})),
    );
    native.server.fallback = success;
  });

  tearDown(() async {
    await native.close();
  });

  final cases = <(String, Future<void> Function(GsdV1ModelsApi))>[
    (
      'getModelStructure (baseClasses/skipMembers werden ignoriert)',
      (api) async {
        await api.getModelStructure(
          classes: 'Vorgang,Adresse',
          baseClasses: 'Basis',
          skipMembers: true,
          rightsControlKey: 'rck-1',
        );
      },
    ),
    (
      'getModelStructure (Defaults)',
      (api) async {
        await api.getModelStructure();
      },
    ),
    (
      'getExtModelStructure',
      (api) async {
        await api.getExtModelStructure(
          classes: 'Vorgang',
          baseClasses: 'Basis',
          skipMembers: true,
          rightsControlKey: 'rck-2',
        );
      },
    ),
    (
      'getExtModelML (GET, nur headerClasses)',
      (api) async {
        await api.getExtModelML(
          headerClasses: <String>['Vorgang'],
          skipMembers: true,
        );
      },
    ),
    (
      'getExtModelML (POST, mit bodyClasses)',
      (api) async {
        await api.getExtModelML(
          headerClasses: <String>['Vorgang'],
          bodyClasses: <String>['Adresse', 'Projekt'],
          skipMembers: true,
        );
      },
    ),
    (
      'getExtModelML (Defaults, bodyClasses null -> GET ohne Body)',
      (api) async {
        await api.getExtModelML();
      },
    ),
    (
      'getExtModelIndexes',
      (api) async {
        await api.getExtModelIndexes(
          classes: 'Vorgang,Adresse',
          rightsControlKey: 'rck-3',
        );
      },
    ),
    (
      'getModelDict',
      (api) async {
        await api.getModelDict(
          'status_labels',
          langID: 'de-DE',
          rightsControlKey: 'rck-4',
        );
      },
    ),
    (
      'getModelDict (Defaults, nur dict)',
      (api) async {
        await api.getModelDict('status_labels');
      },
    ),
  ];

  for (final (name, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callNative(native.api.v1.models);

      expect(native.server.requests, hasLength(1));
      native.expectLegacyWire('models.$name', native.server.requests.single);
    });
  }

  test('getModelStructure sendet weder baseClasses noch skipMembers', () async {
    await native.api.v1.models.getModelStructure(
      classes: 'Vorgang',
      baseClasses: 'Basis',
      skipMembers: true,
    );

    expect(native.server.requests.single.query, <String, String>{
      'classes': 'Vorgang',
    });
  });

  test('getExtModelML schaltet je bodyClasses zwischen GET und POST', () async {
    await native.api.v1.models.getExtModelML(headerClasses: <String>['A']);
    expect(native.server.requests.single.method, 'GET');

    native.server.requests.clear();

    await native.api.v1.models.getExtModelML(bodyClasses: <String>['B']);
    final post = native.server.requests.single;
    expect(post.method, 'POST');
    expect(
      post.body,
      jsonEncode(<String, dynamic>{
        'ml': <String>['B'],
      }),
    );
  });
}
