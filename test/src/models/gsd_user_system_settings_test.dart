@TestOn('vm')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import 'model_test_support.dart';

void main() {
  group('GsdUserSystemSettings', () {
    test('liest die volle Antwort; eine Zahl darf ein String sein', () {
      expect(
        decodeModel(
          GsdUserSystemSettings.fromJson,
          loadV1ModelFixture('user_system_settings.json'),
        ),
        const GsdUserSystemSettings(
          autoDocReadOnOpen: true,
          noPromptInsertNewDocsUserFolders: true,
          noPromptInsertNewDocsGlobalFolders: true,
          dateDefaultReminderTimeSpan: Duration(minutes: 15),
          userRights: 7,
          nextNewDocumentsCount: 3,
          missedCallsCount: 2,
          dateUserObjectName: 'Team',
          eventSettings: {'onOpen': 'Macro1'},
        ),
      );
    });

    test('ohne Felder: Defaults, Erinnerung 5 Minuten', () {
      expect(
        decodeModel(GsdUserSystemSettings.fromJson, <String, Object?>{}),
        const GsdUserSystemSettings(),
      );
      expect(
        const GsdUserSystemSettings().dateDefaultReminderTimeSpan,
        const Duration(minutes: 5),
      );
    });

    test('die Erinnerung rechnet Tage und Stunden in eine Duration um', () {
      expect(
        decodeModel(GsdUserSystemSettings.fromJson, {
          'dateDefaultReminderTimeSpan': 'P1DT2H30S',
        }).dateDefaultReminderTimeSpan,
        const Duration(days: 1, hours: 2, seconds: 30),
      );
    });

    test('falscher Typ wirft mit path', () {
      expect(
        () => decodeModel(GsdUserSystemSettings.fromJson, {'userRights': true}),
        throwsParseExceptionAt('data.userRights'),
      );
    });

    test('eine unlesbare Dauer wirft mit path', () {
      expect(
        () => decodeModel(GsdUserSystemSettings.fromJson, {
          'dateDefaultReminderTimeSpan': '15 Minuten',
        }),
        throwsParseExceptionAt('data.dateDefaultReminderTimeSpan'),
      );
    });
  });
}
