import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/gsd_user_system_settings.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/deduplication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/model_response_policy.dart';
import 'package:meta/meta.dart';

/// Native Benutzer-Einstellungsoperationen der V1-Fassade.
class GsdV1SettingsApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1SettingsApi.internal(this._runtime);
  static const DataResponsePolicy<Object?> _responsePolicy =
      DataResponsePolicy<Object?>();
  static const ModelResponsePolicy<GsdUserSystemSettings>
  _userSystemSettingsResponsePolicy =
      ModelResponsePolicy<GsdUserSystemSettings>(
        GsdUserSystemSettings.fromJson,
      );

  final ApiRuntime _runtime;

  /// Speichert Benutzereinstellungen auf dem Server
  ///
  /// Speichert benutzerspezifische Konfigurationsdaten unter einem Schlüssel.
  /// Ermöglicht die Persistierung von App-Einstellungen zwischen Sessions.
  ///
  /// [key] - Eindeutiger Schlüssel für die Einstellung
  /// [data] - Die zu speichernden Daten als Map
  ///
  /// Returns: `data` der Antwort mit dem Speicherstatus
  ///
  /// Beispiel:
  /// ```dart
  /// Map<String, dynamic> settings = {
  ///   "theme": "dark",
  ///   "language": "de",
  ///   "notifications": true
  /// };
  /// final data = await api.v1.settings.postUserSettings(
  ///   "app_preferences",
  ///   settings
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Speichert eine Benutzereinstellung unter [key]
  /// (`POST v1/userSetting/{key}`); [data] wird als JSON-Body gesendet.
  Future<Object?> postUserSettings(
    String key,
    Map<String, dynamic> data,
  ) {
    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v1,
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
  /// Lädt die systemweiten Einstellungen und Berechtigungen des aktuellen
  /// Benutzers.
  /// Enthält Informationen zu verfügbaren Funktionen und Benutzerrechten.
  ///
  /// [eventMacroName] - Name des Event-Makros für benutzerspezifische
  ///   Anpassungen (optional)
  ///
  /// Returns: [GsdUserSystemSettings] mit Benutzereinstellungen und
  /// Berechtigungen
  ///
  /// Beispiel:
  /// ```dart
  /// final GsdUserSystemSettings settings =
  ///     await api.v1.settings.getUserSystemSettings(
  ///       eventMacroName: "myEvent",
  ///     );
  /// int userRights = settings.userRights;
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt die typisierten Benutzer-Systemeinstellungen
  /// (`GET v1/userSystemSettings`).
  Future<GsdUserSystemSettings> getUserSystemSettings({
    String eventMacroName = '',
  }) {
    final query = <String, String>{};
    if (eventMacroName.isNotEmpty) query['eventMacroName'] = eventMacroName;
    return _runtime.execute(
      ApiRequest<GsdUserSystemSettings>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v1,
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
