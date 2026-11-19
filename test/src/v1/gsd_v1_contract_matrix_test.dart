@TestOn('vm')
library;

// Contract-Matrix je `operationId` der V1-Endpunkte mit DOCUframe-Umschlag:
// Fehlerstatus im Umschlag, ein Body ohne JSON und, bei
// `DeduplicationPolicy.enabled`, zwei gleichzeitige Aufrufe mit einer
// HTTP-Anfrage. Pfad, Query, Body und Rückgabe im Erfolgsfall prüfen die
// Tests je Gruppe gegen `test/fixtures/v1/legacy_wire_contract.json`.
//
// Nicht in der Tabelle: `login` und `logout` (Session-Tests unter
// `test/src/runtime/session/`), der Upload (`upload_executor_test.dart`) und
// `getPreview`, das bei einem Fehlerstatus `null` liefert
// (`gsd_v1_documents_api_test.dart`).

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';
import 'v1_test_support.dart';

/// Ein V1-Endpunkt: Verb, Pfad, Aufruf und ein `data`, das der Endpunkt im
/// Erfolgsfall annimmt. `dedup` markiert `DeduplicationPolicy.enabled`.
typedef _Endpoint = ({
  String method,
  String path,
  Future<Object?> Function(GsdApiClient api) call,
  Object? data,
  bool dedup,
});

final _from = DateTime.utc(2026, 7, 20, 10, 30);
final _to = DateTime.utc(2026, 7, 20, 11, 45);

final _endpoints = <String, _Endpoint>{
  // account
  'v1.account.createDemoAccount': (
    method: 'POST',
    path: '/dfapp/v1/DF/CreateDemoUser',
    call: (api) => api.v1.account.createDemoAccount('pw'),
    data: null,
    dedup: false,
  ),
  // appointments
  'v1.appointments.getAppointments': (
    method: 'GET',
    path: '/dfapp/v1/appointments',
    call: (api) => api.v1.appointments.getAppointments(_from, _to),
    data: <Object?>[],
    dedup: true,
  ),
  'v1.appointments.postAppointments': (
    method: 'POST',
    path: '/dfapp/v1/appointments',
    call: (api) => api.v1.appointments.postAppointments(_from, _to),
    data: null,
    dedup: false,
  ),
  'v1.appointments.postAppointmentsNextFreeDate': (
    method: 'POST',
    path: '/dfapp/v1/appointments/nextFreeDate',
    call: (api) => api.v1.appointments.postAppointmentsNextFreeDate(
      _from,
      _to,
      _to,
      const ['demo'],
    ),
    data: null,
    dedup: false,
  ),
  'v1.appointments.postAppointmentsInvitation': (
    method: 'POST',
    path: '/dfapp/v1/appointments/A1/invitation/decline',
    call: (api) =>
        api.v1.appointments.postAppointmentsInvitation('A1', 'decline', true),
    data: null,
    dedup: false,
  ),
  'v1.appointments.patchAppointmentsRemoveFromSeries': (
    method: 'PATCH',
    path: '/dfapp/v1/appointments/A1/removeFromSeries',
    call: (api) =>
        api.v1.appointments.patchAppointmentsRemoveFromSeries('A1', _from),
    data: null,
    dedup: false,
  ),
  'v1.appointments.patchAppointmentsUpdateAppointment': (
    method: 'PATCH',
    path: '/dfapp/v1/appointments/A1/updateAppointment',
    call: (api) => api.v1.appointments.patchAppointmentsUpdateAppointment(
      'A1',
      _from,
      _to,
    ),
    data: null,
    dedup: false,
  ),
  'v1.appointments.patchAppointmentsCreateException': (
    method: 'PATCH',
    path: '/dfapp/v1/appointments/A1/createException',
    call: (api) => api.v1.appointments.patchAppointmentsCreateException(
      'A1',
      _from,
      _from,
      _to,
    ),
    data: null,
    dedup: false,
  ),
  // authentication
  'v1.authentication.checkSession': (
    method: 'GET',
    path: '/dfapp/_CheckSession',
    call: (api) => api.v1.authentication.checkSession(),
    data: null,
    dedup: true,
  ),
  'v1.authentication.validate2FASecret': (
    method: 'POST',
    path: '/dfapp/v1/2fa/validate',
    call: (api) => api.v1.authentication.validate2FASecret('App', '123456'),
    data: null,
    dedup: false,
  ),
  'v1.authentication.get2FASecret': (
    method: 'GET',
    path: '/dfapp/v1/2fa/secret',
    call: (api) => api.v1.authentication.get2FASecret('App', 'user'),
    data: <String, Object?>{},
    dedup: true,
  ),
  'v1.authentication.create2FASecret': (
    method: 'POST',
    path: '/dfapp/v1/2fa/secret',
    call: (api) => api.v1.authentication.create2FASecret('App'),
    data: null,
    dedup: false,
  ),
  'v1.authentication.refresh2FASecret': (
    method: 'PATCH',
    path: '/dfapp/v1/2fa/secret',
    call: (api) => api.v1.authentication.refresh2FASecret('App', '123456'),
    data: null,
    dedup: false,
  ),
  'v1.authentication.delete2FASecret': (
    method: 'DELETE',
    path: '/dfapp/v1/2fa/secret',
    call: (api) => api.v1.authentication.delete2FASecret('App', '123456'),
    data: null,
    dedup: false,
  ),
  // documents
  'v1.documents.getUploadFile': (
    method: 'GET',
    path: '/dfapp/v1/uploadFile/U1',
    call: (api) => api.v1.documents.getUploadFile('U1'),
    data: <String, Object?>{'size': 1},
    dedup: true,
  ),
  'v1.documents.putDocsRead': (
    method: 'PUT',
    path: '/dfapp/v1/docs/read',
    call: (api) => api.v1.documents.putDocsRead(const ['D1']),
    data: null,
    dedup: false,
  ),
  'v1.documents.putDocsNotNew': (
    method: 'PUT',
    path: '/dfapp/v1/docs/removeDocFromNewDocuments',
    call: (api) => api.v1.documents.putDocsNotNew(const ['D1']),
    data: null,
    dedup: false,
  ),
  'v1.documents.putDocsHistory': (
    method: 'PUT',
    path: '/dfapp/v1/docs/history',
    call: (api) => api.v1.documents.putDocsHistory(const ['D1']),
    data: null,
    dedup: false,
  ),
  'v1.documents.getDocumentPaths': (
    method: 'GET',
    path: '/dfapp/v1/docs/documentPaths/D1',
    call: (api) => api.v1.documents.getDocumentPaths('D1'),
    data: <String, Object?>{'paths': <Object?>[]},
    dedup: true,
  ),
  // folders
  'v1.folders.getFolderByType': (
    method: 'GET',
    path: '/dfapp/v1/folders/type/Inbox',
    call: (api) => api.v1.folders.getFolderByType('Inbox'),
    data: <Object?>[],
    dedup: true,
  ),
  'v1.folders.getFolderByOid': (
    method: 'GET',
    path: '/dfapp/v1/folders/oid/F1',
    call: (api) => api.v1.folders.getFolderByOid('F1'),
    data: <Object?>[],
    dedup: true,
  ),
  'v1.folders.getFolderByPath': (
    method: 'GET',
    path: '/dfapp/v1/folders/path/Projekte',
    call: (api) => api.v1.folders.getFolderByPath('Projekte'),
    data: <Object?>[],
    dedup: true,
  ),
  'v1.folders.postFolders': (
    method: 'POST',
    path: '/dfapp/v1/folders',
    call: (api) => api.v1.folders.postFolders('Neu', 'F1'),
    data: null,
    dedup: false,
  ),
  'v1.folders.deleteFolders': (
    method: 'DELETE',
    path: '/dfapp/v1/folders',
    call: (api) => api.v1.folders.deleteFolders('Temp'),
    data: null,
    dedup: false,
  ),
  'v1.folders.patchFoldersRename': (
    method: 'PATCH',
    path: '/dfapp/v1/folders/rename/F1',
    call: (api) => api.v1.folders.patchFoldersRename('F1', 'Neu'),
    data: null,
    dedup: false,
  ),
  'v1.folders.patchFoldersAdd': (
    method: 'PATCH',
    path: '/dfapp/v1/folders/add/oid/F1',
    call: (api) => api.v1.folders.patchFoldersAdd(
      GsdDocuframeFolderType.oid,
      'F1',
      const ['D1'],
    ),
    data: null,
    dedup: false,
  ),
  'v1.folders.patchFoldersRemoveDocuments': (
    method: 'PATCH',
    path: '/dfapp/v1/folders/remove/oid/F1',
    call: (api) => api.v1.folders.patchFoldersRemoveDocuments(
      GsdDocuframeFolderType.oid,
      'F1',
      const ['D1'],
    ),
    data: null,
    dedup: false,
  ),
  'v1.folders.patchFoldersCopyDocuments': (
    method: 'PATCH',
    path: '/dfapp/v1/folders/copyDocuments',
    call: (api) => api.v1.folders.patchFoldersCopyDocuments(
      GsdDocuframeFolderType.oid,
      'F1',
      const ['D1'],
    ),
    data: null,
    dedup: false,
  ),
  // integrations
  'v1.integrations.postExecuteInterfaceMacro': (
    method: 'POST',
    path: '/dfapp/v1/execute/Makro',
    call: (api) => api.v1.integrations.postExecuteInterfaceMacro('Makro'),
    data: null,
    dedup: false,
  ),
  'v1.integrations.postPrintMacrosExecute': (
    method: 'POST',
    path: '/dfapp/v1/printMacros/execute',
    call: (api) => api.v1.integrations.postPrintMacrosExecute('Text'),
    data: null,
    dedup: false,
  ),
  'v1.integrations.getCalls': (
    method: 'GET',
    path: '/dfapp/v1/calls',
    call: (api) => api.v1.integrations.getCalls(),
    data: <String, Object?>{'calls': <Object?>[]},
    dedup: true,
  ),
  // mail
  'v1.mail.postMail': (
    method: 'POST',
    path: '/dfapp/v1/mail',
    call: (api) => api.v1.mail.postMail(),
    data: null,
    dedup: false,
  ),
  'v1.mail.patchMail': (
    method: 'PATCH',
    path: '/dfapp/v1/mail',
    call: (api) => api.v1.mail.patchMail(oid: 'M1'),
    data: null,
    dedup: false,
  ),
  'v1.mail.postMailSend': (
    method: 'POST',
    path: '/dfapp/v1/mail/send',
    call: (api) => api.v1.mail.postMailSend(),
    data: null,
    dedup: false,
  ),
  'v1.mail.saveMailAttachmentsToDatabase': (
    method: 'POST',
    path: '/dfapp/v1/mail/saveAttachmentsToDB/M1',
    call: (api) => api.v1.mail.saveMailAttachmentsToDatabase('M1'),
    data: null,
    dedup: false,
  ),
  'v1.mail.postMailReply': (
    method: 'POST',
    path: '/dfapp/v1/mail/reply/M1',
    call: (api) => api.v1.mail.postMailReply('M1'),
    data: null,
    dedup: false,
  ),
  'v1.mail.postMailReplyAll': (
    method: 'POST',
    path: '/dfapp/v1/mail/replyAll/M1',
    call: (api) => api.v1.mail.postMailReplyAll('M1'),
    data: null,
    dedup: false,
  ),
  'v1.mail.postMailForward': (
    method: 'POST',
    path: '/dfapp/v1/mail/forward/M1',
    call: (api) => api.v1.mail.postMailForward('M1'),
    data: null,
    dedup: false,
  ),
  'v1.mail.getMailAccounts': (
    method: 'GET',
    path: '/dfapp/v1/mail/accounts',
    call: (api) => api.v1.mail.getMailAccounts(),
    data: <Object?>[],
    dedup: true,
  ),
  'v1.mail.getUserEmailSignatures': (
    method: 'GET',
    path: '/dfapp/v1/userEmailSignatures',
    call: (api) => api.v1.mail.getUserEmailSignatures(),
    data: <Object?>[],
    dedup: true,
  ),
  // messages
  'v1.messages.postMessage': (
    method: 'POST',
    path: '/dfapp/v1/message',
    call: (api) => api.v1.messages.postMessage(const ['demo'], 'Text'),
    data: null,
    dedup: false,
  ),
  'v1.messages.postMessageSend': (
    method: 'POST',
    path: '/dfapp/v1/message/send',
    call: (api) => api.v1.messages.postMessageSend(const ['demo'], 'Text'),
    data: null,
    dedup: false,
  ),
  'v1.messages.patchMessage': (
    method: 'PATCH',
    path: '/dfapp/v1/message/N1',
    call: (api) => api.v1.messages.patchMessage('N1', const ['demo'], 'Text'),
    data: null,
    dedup: false,
  ),
  'v1.messages.patchMessageSend': (
    method: 'PATCH',
    path: '/dfapp/v1/message/send/N1',
    call: (api) =>
        api.v1.messages.patchMessageSend('N1', const ['demo'], 'Text'),
    data: null,
    dedup: false,
  ),
  // models
  'v1.models.getModelStructure': (
    method: 'GET',
    path: '/dfapp/v1/model/structure',
    call: (api) => api.v1.models.getModelStructure(),
    data: <String, Object?>{},
    dedup: true,
  ),
  'v1.models.getExtModelStructure': (
    method: 'GET',
    path: '/dfapp/v1/extModel/structure',
    call: (api) => api.v1.models.getExtModelStructure(),
    data: <String, Object?>{},
    dedup: true,
  ),
  'v1.models.getExtModelML': (
    method: 'GET',
    path: '/dfapp/v1/extModel/ml',
    call: (api) => api.v1.models.getExtModelML(),
    data: <String, Object?>{},
    dedup: true,
  ),
  'v1.models.getExtModelIndexes': (
    method: 'GET',
    path: '/dfapp/v1/extModel/indexes',
    call: (api) => api.v1.models.getExtModelIndexes(),
    data: <String, Object?>{},
    dedup: true,
  ),
  'v1.models.getModelDict': (
    method: 'GET',
    path: '/dfapp/v1/model/dict',
    call: (api) => api.v1.models.getModelDict('status_labels'),
    data: <String, Object?>{},
    dedup: true,
  ),
  // objects
  'v1.objects.getObject': (
    method: 'GET',
    path: '/dfapp/v1/object/O1',
    call: (api) => api.v1.objects.getObject('O1'),
    data: <String, Object?>{'~ObjectID': 'O1'},
    dedup: true,
  ),
  'v1.objects.postObject': (
    method: 'POST',
    path: '/dfapp/v1/object/Vorgang',
    call: (api) => api.v1.objects.postObject('Vorgang', '{}'),
    data: null,
    dedup: false,
  ),
  'v1.objects.patchObject': (
    method: 'PATCH',
    path: '/dfapp/v1/object/O1',
    call: (api) => api.v1.objects.patchObject('O1', '{}'),
    data: null,
    dedup: false,
  ),
  'v1.objects.deleteObject': (
    method: 'DELETE',
    path: '/dfapp/v1/object/O1',
    call: (api) => api.v1.objects.deleteObject('O1'),
    data: null,
    dedup: false,
  ),
  'v1.objects.getObjects': (
    method: 'GET',
    path: '/dfapp/v1/objects/Vorgang',
    call: (api) => api.v1.objects.getObjects('Vorgang'),
    data: <Object?>[],
    dedup: true,
  ),
  'v1.objects.patchObjects': (
    method: 'PATCH',
    path: '/dfapp/v1/objects/Vorgang',
    call: (api) => api.v1.objects.patchObjects('Vorgang'),
    data: null,
    dedup: false,
  ),
  'v1.objects.postAction': (
    method: 'POST',
    path: '/dfapp/v1/action/Vorgang',
    call: (api) => api.v1.objects.postAction('Vorgang'),
    data: null,
    dedup: false,
  ),
  'v1.objects.getLockObject': (
    method: 'GET',
    path: '/dfapp/v1/lock/object/O1',
    call: (api) => api.v1.objects.getLockObject('O1'),
    data: <String, Object?>{'isLocked': false},
    dedup: true,
  ),
  'v1.objects.getIncidentTree': (
    method: 'GET',
    path: '/dfapp/v1/incidentTree/I1',
    call: (api) => api.v1.objects.getIncidentTree('I1'),
    data: <String, Object?>{},
    dedup: true,
  ),
  'v1.objects.setObjectSecurity': (
    method: 'POST',
    path: '/dfapp/v1/setObjectSecurity/O1',
    call: (api) => api.v1.objects.setObjectSecurity('O1', const {'demo': 7}),
    data: null,
    dedup: false,
  ),
  // personal
  'v1.personal.unreadDocuments': (
    method: 'GET',
    path: '/dfapp/v1/personal/unreadDocuments',
    call: (api) => api.v1.personal.getPersonalUnreadDocuments(),
    data: <Object?>[],
    dedup: true,
  ),
  'v1.personal.myTasks': (
    method: 'GET',
    path: '/dfapp/v1/personal/myTasks',
    call: (api) => api.v1.personal.getPersonalMyTasks(),
    data: <Object?>[],
    dedup: true,
  ),
  'v1.personal.emptyRecycleBin': (
    method: 'PATCH',
    path: '/dfapp/v1/personal/emptyRecycleBin',
    call: (api) => api.v1.personal.patchPersonalEmptyRecycleBin(),
    data: null,
    dedup: false,
  ),
  // service
  'v1.service.checkService': (
    method: 'GET',
    path: '/dfapp/_CheckService',
    call: (api) => api.v1.service.checkService(),
    data: <String, Object?>{},
    dedup: true,
  ),
  'v1.service.postLicenseRelease': (
    method: 'POST',
    path: '/dfapp/v1/license/release',
    call: (api) => api.v1.service.postLicenseRelease(const ['App'], 'S1'),
    data: null,
    dedup: false,
  ),
  'v1.service.getVersionInfo': (
    method: 'GET',
    path: '/dfapp/v1/versioninfo',
    call: (api) => api.v1.service.getVersionInfo(),
    data: <String, Object?>{},
    dedup: true,
  ),
  // settings
  'v1.settings.postUserSettings': (
    method: 'POST',
    path: '/dfapp/v1/userSetting/dashboard',
    call: (api) => api.v1.settings.postUserSettings('dashboard', const {}),
    data: null,
    dedup: false,
  ),
  'v1.settings.getUserSystemSettings': (
    method: 'GET',
    path: '/dfapp/v1/userSystemSettings',
    call: (api) => api.v1.settings.getUserSystemSettings(),
    data: <String, Object?>{},
    dedup: true,
  ),
  // timeRecording
  'v1.timeRecording.postPZEClockIn': (
    method: 'POST',
    path: '/dfapp/v1/pze/clockIn',
    call: (api) => api.v1.timeRecording.postPZEClockIn(),
    data: null,
    dedup: false,
  ),
  'v1.timeRecording.postPZEClockOut': (
    method: 'POST',
    path: '/dfapp/v1/pze/clockOut',
    call: (api) => api.v1.timeRecording.postPZEClockOut(),
    data: null,
    dedup: false,
  ),
  'v1.timeRecording.getPZEWorkingTimeKeys': (
    method: 'GET',
    path: '/dfapp/v1/pze/workingTimeKeys',
    call: (api) => api.v1.timeRecording.getPZEWorkingTimeKeys(),
    data: <Object?>[],
    dedup: true,
  ),
  'v1.timeRecording.getPZEWorkingTimeAccounts': (
    method: 'GET',
    path: '/dfapp/v1/pze/workingTimeAccounts',
    call: (api) => api.v1.timeRecording.getPZEWorkingTimeAccounts(),
    data: <Object?>[],
    dedup: true,
  ),
  // xSync
  'v1.xSync.getSyncClassInfo': (
    method: 'GET',
    path: '/dfapp/v1/xSync/ClassInfo/App',
    call: (api) => api.v1.xSync.getSyncClassInfo('App'),
    data: <String, Object?>{'classes': <Object?>[]},
    dedup: true,
  ),
  'v1.xSync.getSyncObjectsOfClass': (
    method: 'POST',
    path: '/dfapp/v1/xSync/dynamic/App/Vorgang',
    call: (api) => api.v1.xSync.getSyncObjectsOfClass('App', 'Vorgang'),
    data: <String, Object?>{},
    dedup: false,
  ),
};

void main() {
  late V1TestHarness harness;

  setUp(() async {
    harness = await V1TestHarness.start();
  });

  tearDown(() => harness.close());

  for (final MapEntry(key: operationId, value: endpoint)
      in _endpoints.entries) {
    group(operationId, () {
      test('ein Fehlerstatus im Umschlag wirft GsdServerException', () async {
        harness.server.enqueueJson(
          endpoint.method,
          endpoint.path,
          body: TestServer.v1Envelope(
            internalStatus: '500',
            statusMessage: 'kaputt',
          ),
        );

        await expectLater(
          endpoint.call(harness.api),
          throwsA(
            isA<GsdServerException>()
                .having((e) => e.internalStatus, 'internalStatus', '500')
                .having((e) => e.statusMessage, 'statusMessage', 'kaputt'),
          ),
        );
      });

      test('ein Body ohne JSON wirft GsdParseException', () async {
        harness.server.enqueue(
          endpoint.method,
          endpoint.path,
          (_) => ScriptedResponse('<html>'),
        );

        await expectLater(
          endpoint.call(harness.api),
          throwsA(
            isA<GsdParseException>().having(
              (e) => e.operationId,
              'operationId',
              operationId,
            ),
          ),
        );
      });

      if (endpoint.dedup) {
        test('zwei gleichzeitige Aufrufe, eine HTTP-Anfrage', () async {
          harness.enqueueSuccess(
            endpoint.method,
            endpoint.path,
            data: endpoint.data,
          );

          final results = await Future.wait([
            endpoint.call(harness.api),
            endpoint.call(harness.api),
          ]);

          expect(harness.server.requests, hasLength(1));
          expect(harness.server.requests.single.path, endpoint.path);
          expect(results.first, results.last);
        });
      }
    });
  }

  test('v1.service.checkServiceWithUri: ein Fehlerstatus im Umschlag wirft '
      'GsdServerException', () async {
    harness.server.enqueueJson(
      'GET',
      '/external/_CheckService',
      body: TestServer.v1Envelope(internalStatus: '500'),
    );

    await expectLater(
      harness.api.v1.service.checkServiceWithUri(
        Uri.parse('${harness.server.baseUrl}/external/_CheckService'),
      ),
      throwsA(isA<GsdServerException>()),
    );
  });

  test('v1.documents.getFile: ein HTTP-Fehlerstatus wirft '
      'GsdHttpException', () async {
    harness.server.enqueue(
      'GET',
      '/dfapp/v1/file/F1',
      (_) => ScriptedResponse('', statusCode: 503),
    );

    await expectLater(
      harness.api.v1.documents.getFile('F1'),
      throwsA(
        isA<GsdHttpException>().having((e) => e.statusCode, 'status', 503),
      ),
    );
  });
}
