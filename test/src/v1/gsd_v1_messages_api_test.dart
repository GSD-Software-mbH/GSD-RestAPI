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

  final cases = <(String, Future<void> Function(GsdV1MessagesApi))>[
    (
      'postMessage',
      (api) async {
        await api.postMessage(
          <String>['alice', 'bob'],
          'Hallo Welt',
          name: 'Titel',
          description: 'Beschreibung',
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
    ),
    (
      'postMessageSend (Defaults)',
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
    ),
    (
      'patchMessage (Defaults)',
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
    ),
    (
      'patchMessageSend (Defaults)',
      (api) async {
        await api.patchMessageSend('msg-2', <String>['alice'], 'Text');
      },
    ),
  ];

  for (final (name, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callNative(native.api.v1.messages);

      expect(native.server.requests, hasLength(1));
      native.expectLegacyWire('messages.$name', native.server.requests.single);
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
