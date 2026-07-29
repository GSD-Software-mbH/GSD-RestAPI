import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';
import 'package:http/http.dart' as http;

/// Compile-Zeit-Nachweis, dass jede freigegebene native V1-Methode auf ihrer
/// dokumentierten Gruppe existiert - und die zwölf Methoden mit
/// Nicht-`RestApiResponse`-Rückgabe ihren Legacy-Rückgabetyp behalten.
///
/// Diese Funktion wird nie AUFGERUFEN; allein ihre Existenz zwingt den
/// Analyzer/Compiler, jede Referenz aufzulösen. Wird eine Methode umbenannt,
/// verschoben oder entfernt - oder ändert sich ein Rückgabetyp der pinned
/// Methoden -, schlägt bereits die KOMPILIERUNG dieser Datei fehl.
void _v1Surface(DOCUframeApi api) {
  // ---- Typisierte Rückgaben (Legacy-Rückgabetyp gepinnt) ----
  final Future<RestApiLoginResponse> Function(String) _ =
      api.v1.authentication.login;
  final Future<RestApi2FASecretResponse> Function(String, String) _ =
      api.v1.authentication.get2FASecret;
  final Future<RestApiCheckServiceResponse> Function() _ =
      api.v1.service.checkService;
  final Future<RestApiCheckServiceResponse> Function(Uri) _ =
      api.v1.service.checkServiceWithUri;
  final Future<RestApiVersionInfoResponse> Function() _ =
      api.v1.service.getVersionInfo;
  final Future<RestApiFileResponse> Function(String) _ =
      api.v1.documents.getFile;
  final Future<Uint8List?> Function(String, String) _ =
      api.v1.documents.getPreview;
  final Future<RestAPIFileUploadController> Function(RestApiUploadFile) _ =
      api.v1.documents.uploadFileWithController;
  final Future<RestApiObjectLockResponse> Function(String) _ =
      api.v1.objects.getLockObject;
  final Future<RestApiSyncClassResponse> Function(String, String) _ =
      api.v1.xSync.getSyncObjectsOfClass;
  final Future<http.Response> Function(String) _ =
      api.v1.integrations.postExecuteInterfaceMacro;
  final Future<RestApiUserSystemSettingsResponse> Function() _ =
      api.v1.settings.getUserSystemSettings;

  // ---- Existenz + Gruppenzugehörigkeit (RestApiResponse-Rückgabe) ----
  // authentication (übrige 6)
  final _ = api.v1.authentication.checkSession;
  final _ = api.v1.authentication.logout;
  final _ = api.v1.authentication.validate2FASecret;
  final _ = api.v1.authentication.create2FASecret;
  final _ = api.v1.authentication.refresh2FASecret;
  final _ = api.v1.authentication.delete2FASecret;
  // service (übrige 1)
  final _ = api.v1.service.postLicenseRelease;
  // folders (9)
  final _ = api.v1.folders.getFolderByType;
  final _ = api.v1.folders.getFolderByOid;
  final _ = api.v1.folders.getFolderByPath;
  final _ = api.v1.folders.postFolders;
  final _ = api.v1.folders.deleteFolders;
  final _ = api.v1.folders.patchFoldersRename;
  final _ = api.v1.folders.patchFoldersAdd;
  final _ = api.v1.folders.patchFoldersRemoveDocuments;
  final _ = api.v1.folders.patchFoldersCopyDocuments;
  // documents (übrige 6)
  final _ = api.v1.documents.putDocsRead;
  final _ = api.v1.documents.putDocsNotNew;
  final _ = api.v1.documents.putDocsHistory;
  final _ = api.v1.documents.uploadFile;
  final _ = api.v1.documents.getUploadFile;
  final _ = api.v1.documents.getDocumentPaths;
  // objects (übrige 9)
  final _ = api.v1.objects.getObject;
  final _ = api.v1.objects.getIncidentTree;
  final _ = api.v1.objects.postObject;
  final _ = api.v1.objects.patchObject;
  final _ = api.v1.objects.deleteObject;
  final _ = api.v1.objects.getObjects;
  final _ = api.v1.objects.postAction;
  final _ = api.v1.objects.patchObjects;
  final _ = api.v1.objects.setObjectSecurity;
  // personal (3)
  final _ = api.v1.personal.getPersonalUnreadDocuments;
  final _ = api.v1.personal.getPersonalMyTasks;
  final _ = api.v1.personal.patchPersonalEmptyRecycleBin;
  // appointments (7)
  final _ = api.v1.appointments.getAppointments;
  final _ = api.v1.appointments.postAppointments;
  final _ = api.v1.appointments.postAppointmentsNextFreeDate;
  final _ = api.v1.appointments.postAppointmentsInvitation;
  final _ = api.v1.appointments.patchAppointmentsRemoveFromSeries;
  final _ = api.v1.appointments.patchAppointmentsUpdateAppointment;
  final _ = api.v1.appointments.patchAppointmentsCreateException;
  // integrations (übrige 2)
  final _ = api.v1.integrations.postPrintMacrosExecute;
  final _ = api.v1.integrations.getCalls;
  // xSync (übrige 1)
  final _ = api.v1.xSync.getSyncClassInfo;
  // mail (9)
  final _ = api.v1.mail.postMail;
  final _ = api.v1.mail.patchMail;
  final _ = api.v1.mail.postMailSend;
  final _ = api.v1.mail.saveMailAttachmentsToDatabase;
  final _ = api.v1.mail.postMailReply;
  final _ = api.v1.mail.postMailReplyAll;
  final _ = api.v1.mail.postMailForward;
  final _ = api.v1.mail.getMailAccounts;
  final _ = api.v1.mail.getUserEmailSignatures;
  // messages (4)
  final _ = api.v1.messages.postMessage;
  final _ = api.v1.messages.postMessageSend;
  final _ = api.v1.messages.patchMessage;
  final _ = api.v1.messages.patchMessageSend;
  // models (5)
  final _ = api.v1.models.getModelStructure;
  final _ = api.v1.models.getExtModelStructure;
  final _ = api.v1.models.getExtModelML;
  final _ = api.v1.models.getExtModelIndexes;
  final _ = api.v1.models.getModelDict;
  // settings (übrige 1)
  final _ = api.v1.settings.postUserSettings;
  // account (1)
  final _ = api.v1.account.createDemoAccount;
  // timeRecording (4)
  final _ = api.v1.timeRecording.postPZEClockIn;
  final _ = api.v1.timeRecording.postPZEClockOut;
  final _ = api.v1.timeRecording.getPZEWorkingTimeKeys;
  final _ = api.v1.timeRecording.getPZEWorkingTimeAccounts;
}

void main() {
  test('native V1-Oberfläche kompiliert vollständig (80 Methoden)', () {
    // Kompiliert die Datei nur, wenn jede Referenz in _v1Surface auflösbar ist.
    expect(_v1Surface, isA<void Function(DOCUframeApi)>());
  });
}
