part of '../restapi.dart';

/// Exception für ungültigen 2FA-Token
/// 
/// Wird geworfen, wenn der Webservice den Fehlercode 342 zurückgibt,
/// was bedeutet, dass ein erforderlicher 2FA-Token ungültig ist.
/// 
/// Diese Exception tritt auf bei:
/// - Ungültigem 2FA-Token
/// 
/// Für alle Fehlercodes siehe: https://docs.gsd.pl/restapi/errorCodes/errorCodes/
class Invalid2FATokenException extends WebServiceException {
  /// Erstellt eine neue Invalid2FATokenException
  /// 
  /// [message] - Beschreibende Fehlernachricht (optional)
  /// [statusCode] - Interner Statuscode vom Webservice (optional)
  /// [statusMessage] - Detaillierte Statusnachricht vom Webservice (optional)
  Invalid2FATokenException([super.message = "", super.statusCode = "", super.statusMessage = ""]);
}
