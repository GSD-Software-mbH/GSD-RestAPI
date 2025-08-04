part of '../restapi.dart';

/// Response-Klasse für Service-Status-Überprüfungen
/// 
/// Erweitert die Basis-RestApiResponse um service-spezifische Informationen:
/// - Anwendungsname und -version
/// - Verfügbare Datenbanken und deren Module
/// - Webservice-Versionsinformationen
/// 
/// Diese Klasse wird verwendet, um den Status und die Verfügbarkeit
/// des REST-API-Services zu überprüfen, bevor eine Verbindung hergestellt wird.
class RestApiCheckServiceResponse extends RestApiResponse {
  /// Version der Anwendung vom Server
  /// 
  /// Enthält die Versionsnummer der REST-API-Anwendung.
  String applicationVersion = "";
  
  /// Name der Anwendung vom Server
  /// 
  /// Enthält den Namen der REST-API-Anwendung (z.B. "GSD-RestApi").
  String applicationName = "";
  
  /// Liste der verfügbaren Datenbanken und deren Module
  /// 
  /// Jede Datenbank enthält eine Liste der verfügbaren Module mit Versionsinformationen.
  List<RestApiDatabase> databases = [];

  /// Erstellt eine RestApiCheckServiceResponse-Instanz
  /// 
  /// Parst die HTTP-Response und extrahiert Service-Informationen,
  /// Datenbanken und Modul-Details.
  /// 
  /// [_httpResponse] - Die HTTP-Response vom CheckService-Endpoint
  /// 
  /// Throws: FormatException wenn 'data' fehlt
  RestApiCheckServiceResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {
        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];

        applicationName = dataJson['applicationName'] ?? "";
        applicationVersion = dataJson['applicationVersion'] ?? "";
        dynamic webservice = dataJson['webservice'];

        if(webservice != null) {
          Map<String, dynamic>? databasesJson = webservice['moduleVersion'];
          applicationVersion = webservice['version'] ?? "";

          // Extrahiere Datenbank- und Modul-Informationen
          if(databasesJson != null && databasesJson.entries.isNotEmpty) {
            for (var i = 0; i < databasesJson.entries.length; i++) {
              RestApiDatabase database = RestApiDatabase(databasesJson.keys.elementAt(i), []);
              dynamic modulesJson = databasesJson.values.elementAt(i);

              if(modulesJson != null) {
                for (var i = 0; i < modulesJson.length; i++) {
                  database.modules.add(RestApiModule(
                    modulesJson[i]["moduleName"] ?? "", 
                    modulesJson[i]["moduleVersion"] ?? ""
                  ));
                }
              }

              databases.add(database);
            }
          }
        }
      }
    }
  }
}
