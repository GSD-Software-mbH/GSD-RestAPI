part of '../gsd_restapi.dart';

/// Response-Klasse für Login-Verschlüsselungsschlüssel-Anfragen
///
/// Diese Klasse wird verwendet, um den öffentlichen Schlüssel für die
/// verschlüsselte Übertragung von Login-Daten zu erhalten. Der Schlüssel
/// wird für RSA- oder AES-Verschlüsselung der Anmeldedaten verwendet.
///
/// Verwendung:
/// - Abrufen des Server-Public-Keys vor Login
/// - Verschlüsselung der Anmeldedaten (v2/login/secure oder v2/login)
/// - Sichere Übertragung von Passwörtern und sensiblen Daten
class RestApiLoginSecureKeyResponse extends RestApiResponse {
  /// Der öffentliche Verschlüsselungsschlüssel vom Server
  ///
  /// Dieser Schlüssel wird verwendet, um die Login-Daten zu verschlüsseln,
  /// bevor sie an den Server gesendet werden. Format und Typ hängen vom
  /// verwendeten Verschlüsselungsverfahren ab (RSA/AES).
  String key = "";

  /// Erstellt eine RestApiLoginSecureKeyResponse-Instanz
  ///
  /// Parst die HTTP-Response und extrahiert den Verschlüsselungsschlüssel.
  ///
  /// [_httpResponse] - Die HTTP-Response vom Login-Key-Endpoint
  ///
  /// Throws: FormatException wenn 'data' oder 'data.key' fehlen
  RestApiLoginSecureKeyResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {
        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];
        if (!dataJson.containsKey("key")) {
          throw const FormatException(
            "missing 'data.key' field in response body",
          );
        } else {
          key = dataJson['key'];
        }
      }
    }
  }
}
