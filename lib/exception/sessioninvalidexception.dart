part of '../gsd_restapi.dart';

/// Exception für ungültige Session
///
/// Wird geworfen, wenn der Webservice den Fehlercode 201 zurückgibt,
/// was bedeutet, dass die aktuelle Session ungültig oder abgelaufen ist.
///
/// Diese Exception tritt auf bei:
/// - Abgelaufener Session
/// - Ungültiger Session-ID
/// - Session wurde serverseitig invalidiert
/// - Benutzer wurde abgemeldet
///
/// Für alle Fehlercodes siehe: https://docs.gsd.pl/restapi/errorCodes/errorCodes/
class SessionInvalidException extends WebServiceException {
  /// Erstellt eine neue SessionInvalidException
  ///
  /// [message] - Beschreibende Fehlernachricht (optional)
  /// [statusCode] - Interner Statuscode vom Webservice (optional)
  /// [statusMessage] - Statusnachricht vom Webservice (optional)
  SessionInvalidException([
    super.message = "",
    super.statusCode = "",
    super.statusMessage = "",
  ]);
}
