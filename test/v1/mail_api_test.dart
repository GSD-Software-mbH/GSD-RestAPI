// ignore_for_file: deprecated_member_use_from_same_package

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

import '../legacy/legacy_test_server.dart';
import 'v1_test_support.dart';

void main() {
  final DateTime startTime = DateTime.utc(2026, 7, 21, 9);
  const List<Map<String, dynamic>> attachments = <Map<String, dynamic>>[
    <String, dynamic>{'name': 'a.pdf', 'oid': 'file-1'},
  ];
  const Map<String, dynamic> templateData = <String, dynamic>{
    'greeting': 'Hallo',
  };

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
      Future<void> Function(V1MailApi),
    )
  >
  cases =
      <
        (
          String,
          Future<void> Function(RestApiDOCUframeManager),
          Future<void> Function(V1MailApi),
        )
      >[
        (
          'postMail',
          (api) async {
            await api.postMail(
              uuid: 'uuid-1',
              from: 'demo',
              to: <String>['a@example.test'],
              cc: <String>['c@example.test'],
              bcc: <String>['b@example.test'],
              name: 'Name',
              description: 'Beschreibung',
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              template: 'tpl-1',
              templateData: templateData,
              attachments: attachments,
              priorityValue: 1,
              priorityText: 'high',
              acknowledgementRequired: true,
              keepCalendar: true,
              startTime: startTime,
              action: 'sendObject',
              actions: '[{"type":"sendObject"}]',
              serialization: '{"type":"class"}',
              assignAddress: true,
              assignProject: true,
              assignProduct: true,
              assignContact: true,
              sendAssignReceiver: true,
              assignAction: true,
            );
          },
          (api) async {
            await api.postMail(
              uuid: 'uuid-1',
              from: 'demo',
              to: <String>['a@example.test'],
              cc: <String>['c@example.test'],
              bcc: <String>['b@example.test'],
              name: 'Name',
              description: 'Beschreibung',
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              template: 'tpl-1',
              templateData: templateData,
              attachments: attachments,
              priorityValue: 1,
              priorityText: 'high',
              acknowledgementRequired: true,
              keepCalendar: true,
              startTime: startTime,
              action: 'sendObject',
              actions: '[{"type":"sendObject"}]',
              serialization: '{"type":"class"}',
              assignAddress: true,
              assignProject: true,
              assignProduct: true,
              assignContact: true,
              sendAssignReceiver: true,
              assignAction: true,
            );
          },
        ),
        (
          'postMail (Defaults, keine optionalen Felder)',
          (api) async {
            await api.postMail();
          },
          (api) async {
            await api.postMail();
          },
        ),
        (
          'patchMail',
          (api) async {
            await api.patchMail(
              uuid: 'uuid-2',
              oid: 'oid-2',
              from: 'demo',
              to: <String>['a@example.test'],
              cc: <String>['c@example.test'],
              bcc: <String>['b@example.test'],
              name: 'Name',
              description: 'Beschreibung',
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              templateData: templateData,
              attachments: attachments,
              priorityValue: 2,
              priorityText: 'low',
              acknowledgementRequired: true,
              keepCalendar: true,
              convertImageDataSrcToFileSrc: true,
              startTime: startTime,
              actions: '[{"type":"x"}]',
            );
          },
          (api) async {
            await api.patchMail(
              uuid: 'uuid-2',
              oid: 'oid-2',
              from: 'demo',
              to: <String>['a@example.test'],
              cc: <String>['c@example.test'],
              bcc: <String>['b@example.test'],
              name: 'Name',
              description: 'Beschreibung',
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              templateData: templateData,
              attachments: attachments,
              priorityValue: 2,
              priorityText: 'low',
              acknowledgementRequired: true,
              keepCalendar: true,
              convertImageDataSrcToFileSrc: true,
              startTime: startTime,
              actions: '[{"type":"x"}]',
            );
          },
        ),
        (
          'patchMail (Defaults)',
          (api) async {
            await api.patchMail();
          },
          (api) async {
            await api.patchMail();
          },
        ),
        (
          'postMailSend',
          (api) async {
            await api.postMailSend(
              uuid: 'uuid-3',
              oid: 'oid-3',
              from: 'demo',
              to: <String>['a@example.test'],
              cc: <String>['c@example.test'],
              bcc: <String>['b@example.test'],
              name: 'Name',
              description: 'Beschreibung',
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              template: 'tpl-3',
              templateData: templateData,
              attachments: attachments,
              priorityValue: 1,
              priorityText: 'high',
              convertImageDataSrcToFileSrc: true,
              acknowledgementRequired: true,
              keepCalendar: true,
              sendAssignReceiver: true,
              startTime: startTime,
              action: 'sendObject',
              actions: '[{"type":"sendObject"}]',
            );
          },
          (api) async {
            await api.postMailSend(
              uuid: 'uuid-3',
              oid: 'oid-3',
              from: 'demo',
              to: <String>['a@example.test'],
              cc: <String>['c@example.test'],
              bcc: <String>['b@example.test'],
              name: 'Name',
              description: 'Beschreibung',
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              template: 'tpl-3',
              templateData: templateData,
              attachments: attachments,
              priorityValue: 1,
              priorityText: 'high',
              convertImageDataSrcToFileSrc: true,
              acknowledgementRequired: true,
              keepCalendar: true,
              sendAssignReceiver: true,
              startTime: startTime,
              action: 'sendObject',
              actions: '[{"type":"sendObject"}]',
            );
          },
        ),
        (
          'postMailSend (Defaults)',
          (api) async {
            await api.postMailSend();
          },
          (api) async {
            await api.postMailSend();
          },
        ),
        (
          'saveMailAttachmentsToDatabase',
          (api) async {
            await api.saveMailAttachmentsToDatabase(
              'mail-oid-1',
              saveAll: true,
              extractSingularZipFile: true,
              indices: const <int>[0, 2, 5],
            );
          },
          (api) async {
            await api.saveMailAttachmentsToDatabase(
              'mail-oid-1',
              saveAll: true,
              extractSingularZipFile: true,
              indices: const <int>[0, 2, 5],
            );
          },
        ),
        (
          'postMailReply',
          (api) async {
            await api.postMailReply(
              'source-1',
              uuid: 'uuid-4',
              oid: 'oid-4',
              from: 'demo',
              to: 'a@example.test',
              cc: 'c@example.test',
              bcc: 'b@example.test',
              name: 'Name',
              description: 'Beschreibung',
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              template: 'tpl-4',
              templateData: templateData,
              attachments: attachments,
              priorityValue: 1,
              priorityText: 'high',
              acknowledgementRequired: true,
              keepCalendar: true,
              startTime: startTime,
              action: 'reply',
              actions: '[{"type":"reply"}]',
              serialization: '{"type":"class"}',
              assignAddress: true,
              assignProject: true,
              assignProduct: true,
              assignContact: true,
              sendAssignReceiver: true,
              assignAction: true,
            );
          },
          (api) async {
            await api.postMailReply(
              'source-1',
              uuid: 'uuid-4',
              oid: 'oid-4',
              from: 'demo',
              to: 'a@example.test',
              cc: 'c@example.test',
              bcc: 'b@example.test',
              name: 'Name',
              description: 'Beschreibung',
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              template: 'tpl-4',
              templateData: templateData,
              attachments: attachments,
              priorityValue: 1,
              priorityText: 'high',
              acknowledgementRequired: true,
              keepCalendar: true,
              startTime: startTime,
              action: 'reply',
              actions: '[{"type":"reply"}]',
              serialization: '{"type":"class"}',
              assignAddress: true,
              assignProject: true,
              assignProduct: true,
              assignContact: true,
              sendAssignReceiver: true,
              assignAction: true,
            );
          },
        ),
        (
          'postMailReply (Defaults)',
          (api) async {
            await api.postMailReply('source-1');
          },
          (api) async {
            await api.postMailReply('source-1');
          },
        ),
        (
          'postMailReplyAll',
          (api) async {
            await api.postMailReplyAll(
              'source-2',
              uuid: 'uuid-5',
              oid: 'oid-5',
              from: 'demo',
              to: 'a@example.test',
              cc: 'c@example.test',
              bcc: 'b@example.test',
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              template: 'tpl-5',
              templateData: templateData,
              attachments: attachments,
              acknowledgementRequired: true,
              keepCalendar: true,
              startTime: startTime,
              action: 'replyAll',
              actions: '[{"type":"replyAll"}]',
              serialization: '{"type":"class"}',
              assignAddress: true,
              assignProject: true,
              assignProduct: true,
              assignContact: true,
              sendAssignReceiver: true,
              assignAction: true,
            );
          },
          (api) async {
            await api.postMailReplyAll(
              'source-2',
              uuid: 'uuid-5',
              oid: 'oid-5',
              from: 'demo',
              to: 'a@example.test',
              cc: 'c@example.test',
              bcc: 'b@example.test',
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              template: 'tpl-5',
              templateData: templateData,
              attachments: attachments,
              acknowledgementRequired: true,
              keepCalendar: true,
              startTime: startTime,
              action: 'replyAll',
              actions: '[{"type":"replyAll"}]',
              serialization: '{"type":"class"}',
              assignAddress: true,
              assignProject: true,
              assignProduct: true,
              assignContact: true,
              sendAssignReceiver: true,
              assignAction: true,
            );
          },
        ),
        (
          'postMailReplyAll (Defaults)',
          (api) async {
            await api.postMailReplyAll('source-2');
          },
          (api) async {
            await api.postMailReplyAll('source-2');
          },
        ),
        (
          'postMailForward',
          (api) async {
            await api.postMailForward(
              'source-3',
              uuid: 'uuid-6',
              oid: 'oid-6',
              from: 'demo',
              to: <String>['a@example.test'],
              cc: <String>['c@example.test'],
              bcc: <String>['b@example.test'],
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              template: 'tpl-6',
              templateData: templateData,
              attachments: attachments,
              acknowledgementRequired: true,
              keepCalendar: true,
              startTime: startTime,
              action: 'forward',
              actions: '[{"type":"forward"}]',
              serialization: '{"type":"class"}',
              assignAddress: true,
              assignProject: true,
              assignProduct: true,
              assignContact: true,
              sendAssignReceiver: true,
              assignAction: true,
            );
          },
          (api) async {
            await api.postMailForward(
              'source-3',
              uuid: 'uuid-6',
              oid: 'oid-6',
              from: 'demo',
              to: <String>['a@example.test'],
              cc: <String>['c@example.test'],
              bcc: <String>['b@example.test'],
              subject: 'Betreff',
              htmlContent: '<p>Hi</p>',
              plainContent: 'Hi',
              template: 'tpl-6',
              templateData: templateData,
              attachments: attachments,
              acknowledgementRequired: true,
              keepCalendar: true,
              startTime: startTime,
              action: 'forward',
              actions: '[{"type":"forward"}]',
              serialization: '{"type":"class"}',
              assignAddress: true,
              assignProject: true,
              assignProduct: true,
              assignContact: true,
              sendAssignReceiver: true,
              assignAction: true,
            );
          },
        ),
        (
          'postMailForward (Defaults)',
          (api) async {
            await api.postMailForward('source-3');
          },
          (api) async {
            await api.postMailForward('source-3');
          },
        ),
        (
          'getMailAccounts',
          (api) async {
            await api.getMailAccounts();
          },
          (api) async {
            await api.getMailAccounts();
          },
        ),
        (
          'getUserEmailSignatures',
          (api) async {
            await api.getUserEmailSignatures();
          },
          (api) async {
            await api.getUserEmailSignatures();
          },
        ),
      ];

  for (final (name, callLegacy, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callLegacy(legacy);
      await callNative(native.api.v1.mail);

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
    'postMail hängt bewusst keinen priority-Block an (Legacy-Quirk)',
    () async {
      await native.api.v1.mail.postMail(priorityValue: 1, priorityText: 'high');

      final Map<String, dynamic> body =
          jsonDecode(native.server.requests.single.body)
              as Map<String, dynamic>;
      expect(body.containsKey('priority'), isFalse);
    },
  );

  test('postMailSend sendet ~UUID und ~ObjectID immer, auch leer', () async {
    await native.api.v1.mail.postMailSend();

    final Map<String, dynamic> body =
        jsonDecode(native.server.requests.single.body) as Map<String, dynamic>;
    expect(body['~UUID'], '');
    expect(body['~ObjectID'], '');
  });

  test('getUserEmailSignatures nutzt den Pfad ohne /mail-Präfix', () async {
    await native.api.v1.mail.getUserEmailSignatures();

    expect(native.server.requests.single.path, '/dfapp/v1/userEmailSignatures');
  });
}
