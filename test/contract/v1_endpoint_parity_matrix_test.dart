import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

/// Ein Eintrag der V1-Paritätsmatrix: Gruppe (= Operation-ID-Segment und
/// Facade-Feld) und öffentlicher Methodenname.
typedef _V1Method = ({String group, String method});

/// Verzeichnis unter `lib/v1/endpoints/`, in dem die Gruppe implementiert ist.
const Map<String, String> _groupDirectory = <String, String>{
  'authentication': 'authentication',
  'service': 'service',
  'folders': 'folders',
  'documents': 'documents',
  'objects': 'objects',
  'personal': 'personal',
  'appointments': 'appointments',
  'integrations': 'integrations',
  'xSync': 'x_sync',
  'mail': 'mail',
  'messages': 'messages',
  'models': 'models',
  'settings': 'settings',
  'account': 'account',
  'timeRecording': 'time_recording',
};

/// Erwartete Methodenanzahl je Gruppe (Summe = 80).
const Map<String, int> _expectedGroupCounts = <String, int>{
  'authentication': 8,
  'service': 4,
  'folders': 9,
  'documents': 9,
  'objects': 10,
  'personal': 3,
  'appointments': 7,
  'integrations': 3,
  'xSync': 2,
  'mail': 9,
  'messages': 4,
  'models': 5,
  'settings': 2,
  'account': 1,
  'timeRecording': 4,
};

/// Die vollständige, freigegebene native V1-Oberfläche: genau 80 Methoden in
/// 15 Gruppen. Diese Tabelle ist der maßgebliche Lock - neue oder entfernte
/// native Endpoints müssen hier bewusst nachgezogen werden.
const List<_V1Method> _matrix = <_V1Method>[
  // authentication (8)
  (group: 'authentication', method: 'login'),
  (group: 'authentication', method: 'checkSession'),
  (group: 'authentication', method: 'logout'),
  (group: 'authentication', method: 'validate2FASecret'),
  (group: 'authentication', method: 'get2FASecret'),
  (group: 'authentication', method: 'create2FASecret'),
  (group: 'authentication', method: 'refresh2FASecret'),
  (group: 'authentication', method: 'delete2FASecret'),
  // service (4)
  (group: 'service', method: 'checkService'),
  (group: 'service', method: 'checkServiceWithUri'),
  (group: 'service', method: 'postLicenseRelease'),
  (group: 'service', method: 'getVersionInfo'),
  // folders (9)
  (group: 'folders', method: 'getFolderByType'),
  (group: 'folders', method: 'getFolderByOid'),
  (group: 'folders', method: 'getFolderByPath'),
  (group: 'folders', method: 'postFolders'),
  (group: 'folders', method: 'deleteFolders'),
  (group: 'folders', method: 'patchFoldersRename'),
  (group: 'folders', method: 'patchFoldersAdd'),
  (group: 'folders', method: 'patchFoldersRemoveDocuments'),
  (group: 'folders', method: 'patchFoldersCopyDocuments'),
  // documents (9)
  (group: 'documents', method: 'getFile'),
  (group: 'documents', method: 'getPreview'),
  (group: 'documents', method: 'putDocsRead'),
  (group: 'documents', method: 'putDocsNotNew'),
  (group: 'documents', method: 'putDocsHistory'),
  (group: 'documents', method: 'uploadFile'),
  (group: 'documents', method: 'uploadFileWithController'),
  (group: 'documents', method: 'getUploadFile'),
  (group: 'documents', method: 'getDocumentPaths'),
  // objects (10)
  (group: 'objects', method: 'getLockObject'),
  (group: 'objects', method: 'getObject'),
  (group: 'objects', method: 'getIncidentTree'),
  (group: 'objects', method: 'postObject'),
  (group: 'objects', method: 'patchObject'),
  (group: 'objects', method: 'deleteObject'),
  (group: 'objects', method: 'getObjects'),
  (group: 'objects', method: 'postAction'),
  (group: 'objects', method: 'patchObjects'),
  (group: 'objects', method: 'setObjectSecurity'),
  // personal (3)
  (group: 'personal', method: 'getPersonalUnreadDocuments'),
  (group: 'personal', method: 'getPersonalMyTasks'),
  (group: 'personal', method: 'patchPersonalEmptyRecycleBin'),
  // appointments (7)
  (group: 'appointments', method: 'getAppointments'),
  (group: 'appointments', method: 'postAppointments'),
  (group: 'appointments', method: 'postAppointmentsNextFreeDate'),
  (group: 'appointments', method: 'postAppointmentsInvitation'),
  (group: 'appointments', method: 'patchAppointmentsRemoveFromSeries'),
  (group: 'appointments', method: 'patchAppointmentsUpdateAppointment'),
  (group: 'appointments', method: 'patchAppointmentsCreateException'),
  // integrations (3)
  (group: 'integrations', method: 'postExecuteInterfaceMacro'),
  (group: 'integrations', method: 'postPrintMacrosExecute'),
  (group: 'integrations', method: 'getCalls'),
  // xSync (2)
  (group: 'xSync', method: 'getSyncClassInfo'),
  (group: 'xSync', method: 'getSyncObjectsOfClass'),
  // mail (9)
  (group: 'mail', method: 'postMail'),
  (group: 'mail', method: 'patchMail'),
  (group: 'mail', method: 'postMailSend'),
  (group: 'mail', method: 'saveMailAttachmentsToDatabase'),
  (group: 'mail', method: 'postMailReply'),
  (group: 'mail', method: 'postMailReplyAll'),
  (group: 'mail', method: 'postMailForward'),
  (group: 'mail', method: 'getMailAccounts'),
  (group: 'mail', method: 'getUserEmailSignatures'),
  // messages (4)
  (group: 'messages', method: 'postMessage'),
  (group: 'messages', method: 'postMessageSend'),
  (group: 'messages', method: 'patchMessage'),
  (group: 'messages', method: 'patchMessageSend'),
  // models (5)
  (group: 'models', method: 'getModelStructure'),
  (group: 'models', method: 'getExtModelStructure'),
  (group: 'models', method: 'getExtModelML'),
  (group: 'models', method: 'getExtModelIndexes'),
  (group: 'models', method: 'getModelDict'),
  // settings (2)
  (group: 'settings', method: 'postUserSettings'),
  (group: 'settings', method: 'getUserSystemSettings'),
  // account (1)
  (group: 'account', method: 'createDemoAccount'),
  // timeRecording (4)
  (group: 'timeRecording', method: 'postPZEClockIn'),
  (group: 'timeRecording', method: 'postPZEClockOut'),
  (group: 'timeRecording', method: 'getPZEWorkingTimeKeys'),
  (group: 'timeRecording', method: 'getPZEWorkingTimeAccounts'),
];

String _groupSource(String group) {
  final String dir = 'lib/v1/endpoints/${_groupDirectory[group]}';
  return Directory(dir)
      .listSync()
      .whereType<File>()
      .where((File file) => file.path.endsWith('.dart'))
      .map((File file) => file.readAsStringSync())
      .join('\n');
}

RegExp _documentedMethod(String method) {
  return RegExp(
    r'(?:^  ///.*\r?\n){5,}'
    r'  Future<.+?>\s+'
    '${RegExp.escape(method)}\\s*\\(',
    multiLine: true,
  );
}

void main() {
  test('die native V1-Oberfläche umfasst genau 80 Methoden', () {
    expect(_matrix.length, 80);
  });

  test('jede (Gruppe, Methode) ist eindeutig (eindeutige Zuordnung)', () {
    final Set<String> seen = <String>{};
    for (final _V1Method entry in _matrix) {
      final String key = '${entry.group}.${entry.method}';
      expect(seen.add(key), isTrue, reason: 'Duplikat: $key');
    }
    expect(seen, hasLength(80));
  });

  test('Methodennamen sind global eindeutig (keine Doppelvergabe)', () {
    final Set<String> methods = _matrix.map((e) => e.method).toSet();
    expect(methods, hasLength(80));
  });

  test('die Gruppenverteilung entspricht der Erwartung (Summe 80)', () {
    final Map<String, int> counts = <String, int>{};
    for (final _V1Method entry in _matrix) {
      counts[entry.group] = (counts[entry.group] ?? 0) + 1;
    }
    expect(counts, _expectedGroupCounts);
    final int total = _expectedGroupCounts.values.fold(0, (a, b) => a + b);
    expect(total, 80);
  });

  test('jede Gruppe hat ein bekanntes Implementierungsverzeichnis', () {
    for (final _V1Method entry in _matrix) {
      expect(
        _groupDirectory.containsKey(entry.group),
        isTrue,
        reason: 'unbekannte Gruppe: ${entry.group}',
      );
    }
  });

  test('jede Methode ist im Quelltext ihrer Gruppe nativ implementiert', () {
    for (final String group in _groupDirectory.keys) {
      final String source = _groupSource(group);
      final Iterable<_V1Method> groupMethods = _matrix.where(
        (e) => e.group == group,
      );
      for (final _V1Method entry in groupMethods) {
        expect(
          source,
          contains('${entry.method}('),
          reason: '${entry.group}.${entry.method} fehlt in $group-Quelltext',
        );
      }
    }
  });

  test('jede öffentliche V1-Methode besitzt eine ausführliche Dartdoc', () {
    for (final String group in _groupDirectory.keys) {
      final String source = _groupSource(group);
      final Iterable<_V1Method> groupMethods = _matrix.where(
        (e) => e.group == group,
      );
      for (final _V1Method entry in groupMethods) {
        expect(
          source,
          matches(_documentedMethod(entry.method)),
          reason:
              '${entry.group}.${entry.method} hat keine ausführliche Dartdoc',
        );
      }
    }
  });

  test('die Dartdoc-Erkennung akzeptiert LF und CRLF', () {
    for (final String lineEnding in <String>['\n', '\r\n']) {
      final String source = <String>[
        '  /// Beschreibung',
        '  ///',
        '  /// Parameter',
        '  ///',
        '  /// Rückgabewert',
        '  Future<void> example() {}',
      ].join(lineEnding);

      expect(source, matches(_documentedMethod('example')));
    }
  });
}
