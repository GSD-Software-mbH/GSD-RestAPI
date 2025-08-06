part of '../gsd_restapi.dart';

/// Response-Klasse für Webservice-Versionsinformationen
/// 
/// Diese Klasse wird verwendet, um detaillierte Informationen über die
/// Version des REST-API-Webservices und seiner Module zu erhalten.
/// 
/// Verwendung:
/// - Kompatibilitätsprüfungen zwischen Client und Server
/// - Feature-Verfügbarkeit basierend auf Versionen
/// - Update-Management und Migrations-Unterstützung
/// - Debugging und Support-Informationen
class RestApiVersionInfoResponse extends RestApiResponse {
  /// Version des Webservices
  /// 
  /// Hauptversion des REST-API-Services im Format "x.y.z".
  String serviceVersion = "";
  
  /// Datum der letzten Strukturänderung
  /// 
  /// Gibt an, wann die Datenbank- oder API-Struktur zuletzt geändert wurde.
  /// Wichtig für Migrations- und Kompatibilitätsprüfungen.
  DateTime? structureChangeDate;
  
  /// Liste der verfügbaren Module mit Versionen
  /// 
  /// Enthält alle installierten Module des Webservices mit ihren
  /// spezifischen Versionsnummern für Feature-Detection.
  List<RestApiDOCUframeModule> modules = [];

  /// Erstellt eine RestApiVersionInfoResponse-Instanz
  /// 
  /// Parst die HTTP-Response und extrahiert Versionsinformationen,
  /// Strukturänderungsdatum und Modul-Details.
  /// 
  /// [_httpResponse] - Die HTTP-Response vom VersionInfo-Endpoint
  /// 
  /// Throws: FormatException wenn 'data' fehlt
  RestApiVersionInfoResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {
        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];
        serviceVersion = dataJson['webserviceVersion'] ?? "";
        dynamic structureChangeDateJson = dataJson['structureChangeDate'];
        dynamic modulesJson = dataJson['listOfModules'];

        // Parse Strukturänderungsdatum
        if(structureChangeDateJson != null) {
          structureChangeDate = DateTime.parse(structureChangeDateJson);
        }

        // Parse Module mit Versionen
        if (modulesJson != null) {
          for (var i = 0; i < modulesJson.length; i++) {
            modules.add(RestApiDOCUframeModule(
              modulesJson[i]["moduleName"] ?? "", 
              modulesJson[i]["moduleVersion"] ?? ""
            ));
          }
        }
      }
    }
  }
}
