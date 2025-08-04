part of '../restapi.dart';

/// Exception für falsche Anmeldedaten
/// 
/// Wird geworfen, wenn der Webservice den Fehlercode 302 zurückgibt,
/// was bedeutet, dass die eingegebenen Anmeldedaten (Benutzername/Passwort)
/// falsch oder ungültig sind.
/// 
/// Diese Exception tritt auf bei:
/// - Falschem Benutzernamen
/// - Falschem Passwort
/// - Deaktiviertem Benutzerkonto
/// - Gesperrtem Benutzerkonto
/// - Ungültigen Anmeldedaten
/// 
/// Für alle Fehlercodes siehe: https://docs.gsd.pl/restapi/errorCodes/errorCodes/
class UserAndPassWrongException implements Exception {
  /// Beschreibende Fehlernachricht über das Anmeldeproblem
  String message;

  /// Der interne Statuscode vom Webservice (normalerweise "302")
  String statusCode;

  /// Die detaillierte Statusnachricht vom Webservice
  String statusMessage;

  /// Erstellt eine neue UserAndPassWrongException
  /// 
  /// [message] - Beschreibende Fehlernachricht (optional)
  /// [statusCode] - Interner Statuscode vom Webservice (optional)
  /// [statusMessage] - Detaillierte Statusnachricht vom Webservice (optional)
  UserAndPassWrongException([this.message = "", this.statusCode = "", this.statusMessage = ""]);

  /// String-Darstellung der Exception
  @override
  String toString() {
    return message;
  }
}
