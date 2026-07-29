part of '../../gsd_restapi.dart';

/// Exception für fehlenden 2FA-Token
///
/// Wird geworfen, wenn der Webservice den Fehlercode 341 zurückgibt,
/// was bedeutet, dass ein erforderlicher 2FA-Token fehlt oder ungültig ist.
///
/// Diese Exception tritt auf bei:
/// - Fehlendem 2FA-Token
///
/// Für alle Fehlercodes siehe: https://docs.gsd.pl/restapi/errorCodes/errorCodes/
class Missing2FATokenException extends WebServiceException {
  /// Erstellt eine neue Missing2FATokenException
  ///
  /// [message] - Beschreibende Fehlernachricht (optional)
  /// [statusCode] - Interner Statuscode vom Webservice (optional)
  /// [statusMessage] - Detaillierte Statusnachricht vom Webservice (optional)
  Missing2FATokenException([
    super.message = "",
    super.statusCode = "",
    super.statusMessage = "",
  ]);
}
