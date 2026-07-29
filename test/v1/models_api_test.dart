// ignore_for_file: deprecated_member_use_from_same_package

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

import '../legacy/legacy_test_server.dart';
import 'v1_test_support.dart';

void main() {
  late LegacyTestServer legacyServer;
  late RestApiDOCUframeManager legacy;
  late V1TestHarness native;

  setUp(() async {
    HttpOverrides.global = null;
    legacyServer = LegacyTestServer();
    await legacyServer.start();
    legacy = RestApiDOCUframeManager(
      config: buildLegacyConfig(
        legacyServer,
        sessionId: V1TestHarness.sessionId,
      ),
    );
    native = await V1TestHarness.start();

    ScriptedResponse success(RecordedRequest _) => ScriptedResponse(
      jsonEncode(v1Envelope(data: <String, dynamic>{'ok': true})),
    );
    legacyServer.fallback = success;
    native.server.fallback = success;
  });

  tearDown(() async {
    legacy.dispose();
    await legacyServer.close();
    await native.close();
  });

  final List<
    (
      String,
      Future<void> Function(RestApiDOCUframeManager),
      Future<void> Function(V1ModelsApi),
    )
  >
  cases =
      <
        (
          String,
          Future<void> Function(RestApiDOCUframeManager),
          Future<void> Function(V1ModelsApi),
        )
      >[
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
          (api) async {
            await api.getModelDict('status_labels');
          },
        ),
      ];

  for (final (name, callLegacy, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callLegacy(legacy);
      await callNative(native.api.v1.models);

      expect(legacyServer.requests, hasLength(1));
      expect(native.server.requests, hasLength(1));
      final RecordedRequest legacyRequest = legacyServer.requests.single;
      final RecordedRequest nativeRequest = native.server.requests.single;
      expect(nativeRequest.method, legacyRequest.method);
      expect(nativeRequest.path, legacyRequest.path);
      expect(nativeRequest.query, legacyRequest.query);
      expect(nativeRequest.body, legacyRequest.body);
      expect(
        nativeRequest.header('sessionid'),
        legacyRequest.header('sessionid'),
      );
      expect(nativeRequest.header('appkey'), legacyRequest.header('appkey'));
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
    final RecordedRequest post = native.server.requests.single;
    expect(post.method, 'POST');
    expect(
      post.body,
      jsonEncode(<String, dynamic>{
        'ml': <String>['B'],
      }),
    );
  });
}
