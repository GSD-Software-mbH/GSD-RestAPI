part of '../restapi.dart';

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
class SessionInvalidException implements Exception {
  /// Beschreibende Fehlernachricht
  String message;

  /// Der interne Statuscode vom Webservice (normalerweise "201")
  String statusCode;

  /// Die Statusnachricht vom Webservice
  String statusMessage;

  /// Erstellt eine neue SessionInvalidException
  /// 
  /// [message] - Beschreibende Fehlernachricht (optional)
  /// [statusCode] - Interner Statuscode vom Webservice (optional)
  /// [statusMessage] - Statusnachricht vom Webservice (optional)
  SessionInvalidException([this.message = "", this.statusCode = "", this.statusMessage = ""]);
}
