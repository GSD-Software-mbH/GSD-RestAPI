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
      Future<void> Function(V1MessagesApi),
    )
  >
  cases =
      <
        (
          String,
          Future<void> Function(RestApiDOCUframeManager),
          Future<void> Function(V1MessagesApi),
        )
      >[
        (
          'postMessage',
          (api) async {
            await api.postMessage(
              <String>['alice', 'bob'],
              'Hallo Welt',
              name: 'Titel',
              description: 'Beschreibung',
              addToIncomingFolder: true,
              originalOid: 'orig-1',
              uuid: 'uuid-1',
              serialization: '{"type":"class"}',
              rightsControlKey: 'rck-1',
              actions: '[{"type":"x"}]',
            );
          },
          (api) async {
            await api.postMessage(
              <String>['alice', 'bob'],
              'Hallo Welt',
              name: 'Titel',
              description: 'Beschreibung',
              addToIncomingFolder: true,
              originalOid: 'orig-1',
              uuid: 'uuid-1',
              serialization: '{"type":"class"}',
              rightsControlKey: 'rck-1',
              actions: '[{"type":"x"}]',
            );
          },
        ),
        (
          'postMessage (Defaults, addToIncomingFolder bewusst false)',
          (api) async {
            await api.postMessage(
              <String>['alice'],
              'Nur Text',
              addToIncomingFolder: false,
            );
          },
          (api) async {
            await api.postMessage(
              <String>['alice'],
              'Nur Text',
              addToIncomingFolder: false,
            );
          },
        ),
        (
          'postMessageSend',
          (api) async {
            await api.postMessageSend(
              <String>['alice', 'bob'],
              'Sende sofort',
              name: 'Titel',
              description: 'Beschreibung',
              originalOid: 'orig-2',
              uuid: 'uuid-2',
              serialization: '{"type":"class"}',
              rightsControlKey: 'rck-2',
              actions: '[{"type":"y"}]',
            );
          },
          (api) async {
            await api.postMessageSend(
              <String>['alice', 'bob'],
              'Sende sofort',
              name: 'Titel',
              description: 'Beschreibung',
              originalOid: 'orig-2',
              uuid: 'uuid-2',
              serialization: '{"type":"class"}',
              rightsControlKey: 'rck-2',
              actions: '[{"type":"y"}]',
            );
          },
        ),
        (
          'postMessageSend (Defaults)',
          (api) async {
            await api.postMessageSend(<String>['alice'], 'Text');
          },
          (api) async {
            await api.postMessageSend(<String>['alice'], 'Text');
          },
        ),
        (
          'patchMessage',
          (api) async {
            await api.patchMessage(
              'msg-1',
              <String>['alice', 'bob'],
              'Aktualisiert',
              name: 'Titel',
              description: 'Beschreibung',
              originalOid: 'orig-3',
              uuid: 'uuid-3',
              serialization: '{"type":"class"}',
              rightsControlKey: 'rck-3',
            );
          },
          (api) async {
            await api.patchMessage(
              'msg-1',
              <String>['alice', 'bob'],
              'Aktualisiert',
              name: 'Titel',
              description: 'Beschreibung',
              originalOid: 'orig-3',
              uuid: 'uuid-3',
              serialization: '{"type":"class"}',
              rightsControlKey: 'rck-3',
            );
          },
        ),
        (
          'patchMessage (Defaults)',
          (api) async {
            await api.patchMessage('msg-1', <String>['alice'], 'Text');
          },
          (api) async {
            await api.patchMessage('msg-1', <String>['alice'], 'Text');
          },
        ),
        (
          'patchMessageSend',
          (api) async {
            await api.patchMessageSend(
              'msg-2',
              <String>['alice', 'bob'],
              'Final',
              name: 'Titel',
              description: 'Beschreibung',
              originalOid: 'orig-4',
              uuid: 'uuid-4',
              serialization: '{"type":"class"}',
              rightsControlKey: 'rck-4',
            );
          },
          (api) async {
            await api.patchMessageSend(
              'msg-2',
              <String>['alice', 'bob'],
              'Final',
              name: 'Titel',
              description: 'Beschreibung',
              originalOid: 'orig-4',
              uuid: 'uuid-4',
              serialization: '{"type":"class"}',
              rightsControlKey: 'rck-4',
            );
          },
        ),
        (
          'patchMessageSend (Defaults)',
          (api) async {
            await api.patchMessageSend('msg-2', <String>['alice'], 'Text');
          },
          (api) async {
            await api.patchMessageSend('msg-2', <String>['alice'], 'Text');
          },
        ),
      ];

  for (final (name, callLegacy, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callLegacy(legacy);
      await callNative(native.api.v1.messages);

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

  test(
    'patchMessage sendet keinen actions-Query (nur post* unterstützt ihn)',
    () async {
      await native.api.v1.messages.patchMessage(
        'msg-1',
        <String>['alice'],
        'Text',
        serialization: '{"type":"class"}',
        rightsControlKey: 'rck',
      );

      expect(native.server.requests.single.query, <String, String>{
        'serialization': '{"type":"class"}',
        'rightsControlKey': 'rck',
      });
    },
  );

  test('patchMessageSend hängt die oid an /message/send an', () async {
    await native.api.v1.messages.patchMessageSend('msg-2', <String>[
      'alice',
    ], 'Text');

    expect(native.server.requests.single.path, '/dfapp/v1/message/send/msg-2');
  });
}
