part of '../docuframe_api.dart';

/// Öffentliche Gruppen der nativen V1-API.
class DocuframeV1Api {
  /// Termine, Serien, Einladungen und Terminausnahmen.
  V1AppointmentsApi appointments;

  /// Login und Logout auf dem gemeinsamen Sessionzustand der Fassade.
  V1AuthenticationApi authentication;

  /// Service-, Lizenz- und Versionsinformationen.
  V1ServiceApi service;

  /// Ordnernavigation und Ordneroperationen.
  V1FoldersApi folders;

  /// Dokument-, Binär- und Uploadoperationen.
  V1DocumentsApi documents;

  /// Makro-, Druck- und Telefonie-Integrationen.
  V1IntegrationsApi integrations;

  /// Synchronisationsoperationen unter `v1/xSync`.
  V1XSyncApi xSync;

  /// E-Mail-Operationen (erstellen, senden, beantworten, weiterleiten).
  V1MailApi mail;

  /// Interne Nachrichten (erstellen, senden, bearbeiten).
  V1MessagesApi messages;

  /// Modellstruktur, erweitertes Modell und Wörterbücher.
  V1ModelsApi models;

  /// Benutzer- und Systemeinstellungen.
  V1SettingsApi settings;

  /// Kontooperationen (z.B. Demo-Benutzer).
  V1AccountApi account;

  /// Personalzeiterfassung (PZE): Ein-/Ausstempeln, Zeitschlüssel, Konten.
  V1TimeRecordingApi timeRecording;

  /// Einzel-, Massen-, Aktions- und Sicherheitsoperationen für Objekte.
  V1ObjectsApi objects;

  /// Persönliche Dokumente, Aufgaben und Papierkorboperationen.
  V1PersonalApi personal;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  DocuframeV1Api.internal(
    ApiRuntime runtime,
    SessionCoordinator sessionCoordinator,
    UploadExecutor uploadExecutor,
  ) : appointments = V1AppointmentsApi.internal(runtime),
      authentication = V1AuthenticationApi.internal(
        runtime,
        sessionCoordinator,
      ),
      folders = V1FoldersApi.internal(runtime),
      documents = V1DocumentsApi.internal(runtime, uploadExecutor),
      integrations = V1IntegrationsApi.internal(runtime),
      xSync = V1XSyncApi.internal(runtime),
      mail = V1MailApi.internal(runtime),
      messages = V1MessagesApi.internal(runtime),
      models = V1ModelsApi.internal(runtime),
      objects = V1ObjectsApi.internal(runtime),
      personal = V1PersonalApi.internal(runtime),
      service = V1ServiceApi.internal(runtime),
      settings = V1SettingsApi.internal(runtime),
      account = V1AccountApi.internal(runtime),
      timeRecording = V1TimeRecordingApi.internal(runtime);
}
