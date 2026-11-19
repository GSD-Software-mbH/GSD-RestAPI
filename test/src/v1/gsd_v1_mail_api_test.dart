@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';
import 'v1_test_support.dart';

void main() {
  final startTime = DateTime.utc(2026, 7, 21, 9);
  const attachments = <Map<String, dynamic>>[
    <String, dynamic>{'name': 'a.pdf', 'oid': 'file-1'},
  ];
  const templateData = <String, dynamic>{
    'greeting': 'Hallo',
  };

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

  final cases = <(String, Future<void> Function(GsdV1MailApi))>[
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
    ),
    (
      'postMail (Defaults, keine optionalen Felder)',
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
    ),
    (
      'patchMail (Defaults)',
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
    ),
    (
      'postMailSend (Defaults)',
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
    ),
    (
      'postMailReply (Defaults)',
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
    ),
    (
      'postMailReplyAll (Defaults)',
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
    ),
    (
      'postMailForward (Defaults)',
      (api) async {
        await api.postMailForward('source-3');
      },
    ),
    (
      'getMailAccounts',
      (api) async {
        await api.getMailAccounts();
      },
    ),
    (
      'getUserEmailSignatures',
      (api) async {
        await api.getUserEmailSignatures();
      },
    ),
  ];

  for (final (name, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callNative(native.api.v1.mail);

      expect(native.server.requests, hasLength(1));
      native.expectLegacyWire('mail.$name', native.server.requests.single);
    });
  }

  test(
    'postMail hängt bewusst keinen priority-Block an (Legacy-Quirk)',
    () async {
      await native.api.v1.mail.postMail(priorityValue: 1, priorityText: 'high');

      final body =
          jsonDecode(native.server.requests.single.body)
              as Map<String, dynamic>;
      expect(body.containsKey('priority'), isFalse);
    },
  );

  test('postMailSend sendet ~UUID und ~ObjectID immer, auch leer', () async {
    await native.api.v1.mail.postMailSend();

    final body =
        jsonDecode(native.server.requests.single.body) as Map<String, dynamic>;
    expect(body['~UUID'], '');
    expect(body['~ObjectID'], '');
  });

  test('getUserEmailSignatures nutzt den Pfad ohne /mail-Präfix', () async {
    await native.api.v1.mail.getUserEmailSignatures();

    expect(native.server.requests.single.path, '/dfapp/v1/userEmailSignatures');
  });
}
