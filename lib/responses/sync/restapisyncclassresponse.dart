part of '../../gsd_restapi.dart';

/// Response-Klasse für Synchronisations-API-Aufrufe
///
/// Diese Klasse verarbeitet die Antworten von Synchronisations-Endpunkten,
/// die Container-basierte Daten mit Klassen zurückgeben.
class RestApiSyncClassResponse extends RestApiResponse {
  /// Liste aller verfügbaren Container-IDs
  List<String> allContainers = [];

  /// Map der Container-Daten
  Map<String, RestApiSyncContainer> containers = {};

  /// Erstellt eine RestApiSyncClassResponse-Instanz
  ///
  /// Parst die HTTP-Response und extrahiert Container-Informationen.
  ///
  /// [_httpResponse] - Die HTTP-Response vom Sync-Endpoint
  RestApiSyncClassResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {
        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];

        // Parse allContainers
        if (dataJson['allContainers'] != null) {
          allContainers = List<String>.from(dataJson['allContainers']);
        }

        // Parse Container-Daten
        for (String containerId in allContainers) {
          if (dataJson.containsKey(containerId)) {
            containers[containerId] = RestApiSyncContainer.fromJson(
              dataJson[containerId],
            );
          }
        }
      }
    }
  }
}
