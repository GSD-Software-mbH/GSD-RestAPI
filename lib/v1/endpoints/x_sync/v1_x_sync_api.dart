part of '../../../docuframe_api.dart';

/// Native Synchronisationsoperationen unter `v1/xSync`.
class V1XSyncApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();
  static const LegacyResponsePolicy<RestApiSyncClassResponse>
  _syncClassResponsePolicy = LegacyResponsePolicy<RestApiSyncClassResponse>(
    RestApiSyncClassResponse.new,
  );

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1XSyncApi.internal(this._runtime);

  /// Ruft Synchronisations-Klassen-Informationen für eine Anwendung ab.
  ///
  /// Lädt die verfügbaren Synchronisations-Klassen und deren Metadaten für
  /// eine bestimmte Anwendung. Die Informationen beschreiben die für xSync
  /// verfügbaren Datenstrukturen und Eigenschaften.
  ///
  /// [appName] - Name der Anwendung, deren Klassen abgerufen werden
  ///
  /// Returns: [RestApiResponse] mit den Klasseninformationen als JSON
  ///
  /// Throws: HttpRequestException bei HTTP-Fehlern
  /// Throws: SessionInvalidException bei ungültiger Session
  Future<RestApiResponse> getSyncClassInfo(String appName) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v1,
        path: '/xSync/ClassInfo/$appName',
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _responsePolicy,
        operationId: 'v1.xSync.getSyncClassInfo',
      ),
    );
  }

  /// Ruft Synchronisations-Objekte einer bestimmten Klasse ab.
  ///
  /// Lädt die aktuellen Daten und Metadaten der angegebenen xSync-Klasse.
  /// Bereits bekannte Containerstände können mitgegeben werden, um nur die
  /// nachfolgenden Datensätze abzurufen.
  ///
  /// [appName] - Name der Anwendung
  /// [className] - Name der abzurufenden Synchronisations-Klasse
  /// [nextContainers] - Zuletzt bekannte Marker und Revisionen je Container
  /// [maxRecords] - Optionale maximale Anzahl zurückgegebener Datensätze
  ///
  /// Returns: [RestApiSyncClassResponse] mit den synchronisierten Objektdaten
  ///
  /// Throws: HttpRequestException bei HTTP-Fehlern
  /// Throws: SessionInvalidException bei ungültiger Session
  Future<RestApiSyncClassResponse> getSyncObjectsOfClass(
    String appName,
    String className, {
    List<RestApiSyncContainer> nextContainers = const [],
    int? maxRecords,
  }) {
    final Map<String, dynamic> bodyMap = <String, dynamic>{};

    if (maxRecords != null) {
      bodyMap['maxRecords'] = maxRecords;
    }

    for (final RestApiSyncContainer container in nextContainers) {
      bodyMap[container.containerId] = <String, dynamic>{
        'lastMarker': container.nextMarker,
        'revision': container.revision,
      };
    }

    return _runtime.execute(
      ApiRequest<RestApiSyncClassResponse>(
        method: ApiHttpMethod.post,
        version: ApiVersion.v1,
        path: '/xSync/dynamic/$appName/$className',
        body: bodyMap.isNotEmpty ? jsonEncode(bodyMap) : null,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _syncClassResponsePolicy,
        operationId: 'v1.xSync.getSyncObjectsOfClass',
      ),
    );
  }
}
