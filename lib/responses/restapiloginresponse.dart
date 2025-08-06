part of '../gsd_restapi.dart';

/// Response-Klasse für Login-API-Anfragen
/// 
/// Erweitert die Basis-RestApiResponse um login-spezifische Daten:
/// - Session-ID für nachfolgende API-Aufrufe
/// - Liste der verfügbaren Anwendungen/ACLs
/// - Hilfsmethoden für Anwendungsprüfungen
/// 
/// Diese Klasse wird nach erfolgreicher Benutzeranmeldung verwendet.
class RestApiLoginResponse extends RestApiResponse {
  /// Session-ID aus der HTTP-Response
  /// 
  /// Diese ID wird für alle nachfolgenden API-Aufrufe benötigt
  /// und identifiziert die aktuelle Benutzersession eindeutig.
  String sessionId = "";
  
  /// Liste der verfügbaren Anwendungen für den angemeldeten Benutzer
  /// 
  /// Enthält alle Anwendungen, auf die der Benutzer Zugriff hat,
  /// basierend auf den Access Control Lists (ACLs).
  List<String> applications = [];

  /// Erstellt eine RestApiLoginResponse-Instanz
  /// 
  /// Parst die HTTP-Response und extrahiert Session-ID und Anwendungsliste.
  /// 
  /// [_httpResponse] - Die HTTP-Response vom Login-Endpoint
  /// 
  /// Throws: FormatException wenn 'data' oder 'data.sessionId' fehlen
  RestApiLoginResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {
        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];
        if (!dataJson.containsKey("sessionId")) {
          throw const FormatException("missing 'data.sessionId' field in response body");
        } else {
          sessionId = dataJson['sessionId'];
        }

        // Extrahiere verfügbare Anwendungen aus ACLs
        dynamic acls = dataJson["acls"];
        dynamic currentAclApplication;

        if(acls == null) {
          return;
        }

        for (var i = 0; i < acls.length; i++) {
          currentAclApplication = acls[i]["application"];

          if(currentAclApplication != null) {
            applications.add(currentAclApplication);
          }
        }
      }
    }
  }

  /// Überprüft, ob der Benutzer Zugriff auf eine bestimmte Anwendung hat
  /// 
  /// [application] - Name der zu prüfenden Anwendung
  /// 
  /// Returns: true wenn Zugriff vorhanden, sonst false
  /// 
  /// Beispiel:
  /// ```dart
  /// if (loginResponse.hasApplication('GSD-DFApp')) {
  ///   // Benutzer hat Zugriff auf DFApp
  /// }
  /// ```
  bool hasApplication(String application) {
    return applications.contains(application);
  }
}
