part of '../gsd_restapi.dart';

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
class UserAndPassWrongException extends WebServiceException {
  /// Erstellt eine neue UserAndPassWrongException
  ///
  /// [message] - Beschreibende Fehlernachricht (optional)
  /// [statusCode] - Interner Statuscode vom Webservice (optional)
  /// [statusMessage] - Detaillierte Statusnachricht vom Webservice (optional)
  UserAndPassWrongException([
    super.message = "",
    super.statusCode = "",
    super.statusMessage = "",
  ]);
}
