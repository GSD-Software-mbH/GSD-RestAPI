part of '../../../docuframe_api.dart';

/// Native persönliche V1-Operationen für den angemeldeten Benutzer.
class V1PersonalApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1PersonalApi.internal(this._runtime);

  /// Ruft ungelesene Dokumente des aktuellen Benutzers ab
  ///
  /// Lädt alle Dokumente, die vom aktuellen Benutzer noch nicht gelesen wurden.
  /// Hilfreich für Benachrichtigungen und To-Do-Listen.
  ///
  /// Returns: [RestApiResponse] mit der Liste ungelesener Dokumente
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.personal.getPersonalUnreadDocuments();
  /// if (response.isOk) {
  ///   List unreadDocs = response.data['documents'];
  ///   print("${unreadDocs.length} ungelesene Dokumente");
  /// }
  /// ```
  Future<RestApiResponse> getPersonalUnreadDocuments() => _execute(
    ApiHttpMethod.get,
    '/personal/unreadDocuments',
    'unreadDocuments',
  );

  /// Ruft persönliche Aufgaben des aktuellen Benutzers ab
  ///
  /// Lädt alle dem aktuellen Benutzer zugewiesenen Aufgaben und Aktionen.
  /// Enthält sowohl offene als auch abgeschlossene Aufgaben.
  ///
  /// Returns: [RestApiResponse] mit der Liste persönlicher Aufgaben
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.personal.getPersonalMyTasks();
  /// if (response.isOk) {
  ///   List tasks = response.data['tasks'];
  ///   print("${tasks.length} Aufgaben gefunden");
  /// }
  /// ```
  Future<RestApiResponse> getPersonalMyTasks() =>
      _execute(ApiHttpMethod.get, '/personal/myTasks', 'myTasks');

  /// Leert den Papierkorb des aktuellen Benutzers
  ///
  /// Löscht alle Objekte aus dem persönlichen Papierkorb endgültig.
  /// Diese Aktion kann nicht rückgängig gemacht werden.
  ///
  /// Returns: [RestApiResponse] mit dem Status der Papierkorb-Leerung
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.personal.patchPersonalEmptyRecycleBin();
  /// if (response.isOk) {
  ///   print("Papierkorb erfolgreich geleert");
  /// }
  /// ```
  Future<RestApiResponse> patchPersonalEmptyRecycleBin() => _execute(
    ApiHttpMethod.patch,
    '/personal/emptyRecycleBin',
    'emptyRecycleBin',
  );

  Future<RestApiResponse> _execute(
    ApiHttpMethod method,
    String path,
    String operation,
  ) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: method,
        version: ApiVersion.v1,
        path: path,
        authentication: AuthenticationPolicy.session,
        deduplication: method == ApiHttpMethod.get
            ? DeduplicationPolicy.enabled
            : DeduplicationPolicy.disabled,
        responsePolicy: _responsePolicy,
        operationId: 'v1.personal.$operation',
      ),
    );
  }
}
