part of '../../../docuframe_api.dart';

/// Native Benutzer-Einstellungsoperationen der V1-Fassade.
class V1SettingsApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();
  static const LegacyResponsePolicy<RestApiUserSystemSettingsResponse>
  _userSystemSettingsResponsePolicy =
      LegacyResponsePolicy<RestApiUserSystemSettingsResponse>(
        RestApiUserSystemSettingsResponse.new,
      );

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1SettingsApi.internal(this._runtime);

  /// Speichert Benutzereinstellungen auf dem Server
  ///
  /// Speichert benutzerspezifische Konfigurationsdaten unter einem Schlüssel.
  /// Ermöglicht die Persistierung von App-Einstellungen zwischen Sessions.
  ///
  /// [key] - Eindeutiger Schlüssel für die Einstellung
  /// [data] - Die zu speichernden Daten als Map
  ///
  /// Returns: [RestApiResponse] mit dem Speicherstatus
  ///
  /// Beispiel:
  /// ```dart
  /// Map<String, dynamic> settings = {
  ///   "theme": "dark",
  ///   "language": "de",
  ///   "notifications": true
  /// };
  /// RestApiResponse response = await api.v1.settings.postUserSettings(
  ///   "app_preferences",
  ///   settings
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Speichert eine Benutzereinstellung unter [key]
  /// (`POST v1/userSetting/{key}`); [data] wird als JSON-Body gesendet.
  Future<RestApiResponse> postUserSettings(
    String key,
    Map<String, dynamic> data,
  ) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.post,
        version: ApiVersion.v1,
        path: '/userSetting/$key',
        body: jsonEncode(data),
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v1.settings.postUserSettings',
      ),
    );
  }

  /// Ruft Benutzer-Systemeinstellungen ab
  ///
  /// Lädt die systemweiten Einstellungen und Berechtigungen des aktuellen Benutzers.
  /// Enthält Informationen zu verfügbaren Funktionen und Benutzerrechten.
  ///
  /// [eventMacroName] - Name des Event-Makros für benutzerspezifische Anpassungen (optional)
  ///
  /// Returns: [RestApiUserSystemSettingsResponse] mit Benutzereinstellungen und Berechtigungen
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiUserSystemSettingsResponse response = await api.v1.settings.getUserSystemSettings(eventMacroName: "myEvent");
  /// if (response.isOk) {
  ///   Map<String, dynamic> settings = response.settings;
  ///   bool canEditDocuments = response.hasPermission("edit_documents");
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt die typisierten Benutzer-Systemeinstellungen
  /// (`GET v1/userSystemSettings`).
  Future<RestApiUserSystemSettingsResponse> getUserSystemSettings({
    String eventMacroName = '',
  }) {
    final Map<String, String> query = <String, String>{};
    if (eventMacroName.isNotEmpty) query['eventMacroName'] = eventMacroName;
    return _runtime.execute(
      ApiRequest<RestApiUserSystemSettingsResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v1,
        path: '/userSystemSettings',
        queryParameters: query.isEmpty ? null : query,
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _userSystemSettingsResponsePolicy,
        operationId: 'v1.settings.getUserSystemSettings',
      ),
    );
  }
}
