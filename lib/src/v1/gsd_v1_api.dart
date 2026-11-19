import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:gsd_restapi/src/runtime/transport/upload_executor.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_account_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_appointments_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_authentication_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_documents_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_folders_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_integrations_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_mail_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_messages_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_models_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_objects_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_personal_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_service_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_settings_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_time_recording_api.dart';
import 'package:gsd_restapi/src/v1/gsd_v1_x_sync_api.dart';
import 'package:meta/meta.dart';

/// Öffentliche Gruppen der nativen V1-API.
class GsdV1Api {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1Api.internal(
    ApiRuntime runtime,
    SessionCoordinator sessionCoordinator,
    UploadExecutor uploadExecutor,
  ) : appointments = GsdV1AppointmentsApi.internal(runtime),
      authentication = GsdV1AuthenticationApi.internal(
        runtime,
        sessionCoordinator,
      ),
      folders = GsdV1FoldersApi.internal(runtime),
      documents = GsdV1DocumentsApi.internal(runtime, uploadExecutor),
      integrations = GsdV1IntegrationsApi.internal(runtime),
      xSync = GsdV1XSyncApi.internal(runtime),
      mail = GsdV1MailApi.internal(runtime),
      messages = GsdV1MessagesApi.internal(runtime),
      models = GsdV1ModelsApi.internal(runtime),
      objects = GsdV1ObjectsApi.internal(runtime),
      personal = GsdV1PersonalApi.internal(runtime),
      service = GsdV1ServiceApi.internal(runtime),
      settings = GsdV1SettingsApi.internal(runtime),
      account = GsdV1AccountApi.internal(runtime),
      timeRecording = GsdV1TimeRecordingApi.internal(runtime);

  /// Termine, Serien, Einladungen und Terminausnahmen.
  final GsdV1AppointmentsApi appointments;

  /// Login und Logout auf dem gemeinsamen Sessionzustand der Fassade.
  final GsdV1AuthenticationApi authentication;

  /// Service-, Lizenz- und Versionsinformationen.
  final GsdV1ServiceApi service;

  /// Ordnernavigation und Ordneroperationen.
  final GsdV1FoldersApi folders;

  /// Dokument-, Binär- und Uploadoperationen.
  final GsdV1DocumentsApi documents;

  /// Makro-, Druck- und Telefonie-Integrationen.
  final GsdV1IntegrationsApi integrations;

  /// Synchronisationsoperationen unter `v1/xSync`.
  final GsdV1XSyncApi xSync;

  /// E-Mail-Operationen (erstellen, senden, beantworten, weiterleiten).
  final GsdV1MailApi mail;

  /// Interne Nachrichten (erstellen, senden, bearbeiten).
  final GsdV1MessagesApi messages;

  /// Modellstruktur, erweitertes Modell und Wörterbücher.
  final GsdV1ModelsApi models;

  /// Benutzer- und Systemeinstellungen.
  final GsdV1SettingsApi settings;

  /// Kontooperationen (z.B. Demo-Benutzer).
  final GsdV1AccountApi account;

  /// Personalzeiterfassung (PZE): Ein-/Ausstempeln, Zeitschlüssel, Konten.
  final GsdV1TimeRecordingApi timeRecording;

  /// Einzel-, Massen-, Aktions- und Sicherheitsoperationen für Objekte.
  final GsdV1ObjectsApi objects;

  /// Persönliche Dokumente, Aufgaben und Papierkorboperationen.
  final GsdV1PersonalApi personal;
}
