part of '../gsd_restapi.dart';

/// Antwort-Klasse für 2FA (Zwei-Faktor-Authentifizierung) Secret-Anfragen
///
/// Diese Klasse verarbeitet die Antwort des Servers bei Anfragen bezüglich
/// der 2FA-Konfiguration und des Status des Benutzers.
class RestApi2FASecretResponse extends RestApiResponse {
  /// Gibt an, ob 2FA für den Benutzer aktiviert ist
  ///
  /// true = 2FA ist aktiviert und wird verwendet
  /// false = 2FA ist nicht aktiviert
  bool isActivated = false;

  /// Gibt an, ob die 2FA-Konfiguration bestätigt wurde
  ///
  /// true = Der Benutzer hat die 2FA-Einrichtung erfolgreich bestätigt
  /// false = Die 2FA-Einrichtung wurde noch nicht bestätigt
  bool isConfirmed = false;

  /// Numerischer Status der Zwei-Faktor-Authentifizierung
  ///
  /// Entspricht den Werten aus [RestApi2FAStatus]:
  /// - 0: Nicht verfügbar (na)
  /// - 1: Deaktiviert (deactivated)
  /// - 2: Optional (optional)
  /// - 3: Erzwungen (forced)
  RestApi2FAStatus twoFaStatus = RestApi2FAStatus.na;

  /// Erstellt eine neue RestApi2FASecretResponse-Instanz
  ///
  /// Parst die HTTP-Antwort und extrahiert die 2FA-relevanten Informationen
  /// aus dem JSON-Response. Die Daten werden aus dem "data"-Feld der
  /// Server-Antwort gelesen.
  ///
  /// [_httpResponse] - Die HTTP-Antwort vom Server
  ///
  /// Throws: [FormatException] wenn das "data"-Feld in der Antwort fehlt
  RestApi2FASecretResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {
        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];

        isActivated = dataJson["isActivated"] ?? false;
        isConfirmed = dataJson["isConfirmed"] ?? false;
        twoFaStatus = RestApi2FAStatus.values[dataJson["2faStatus"] ?? 0];
      }
    }
  }
}
