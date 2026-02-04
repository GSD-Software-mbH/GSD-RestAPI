part of '../gsd_restapi.dart';

/// Exception für fehlende Token oder Session
///
/// Wird geworfen, wenn der Webservice den Fehlercode 204 zurückgibt,
/// was bedeutet, dass der erforderliche Token oder die Session-ID
/// in der Anfrage fehlen.
///
/// Diese Exception tritt auf bei:
/// - Fehlender Session-ID im Header
/// - Fehlender App-Key/Token
/// - Nicht gesetzten Authentifizierungs-Headern
/// - Ungültigen oder leeren Session-Daten
/// - Nicht initialisierten API-Clients
///
/// Für alle Fehlercodes siehe: https://docs.gsd.pl/restapi/errorCodes/errorCodes/
class TokenOrSessionIsMissingException extends WebServiceException {
  /// Erstellt eine neue TokenOrSessionIsMissingException
  ///
  /// [message] - Beschreibende Fehlernachricht (optional)
  /// [statusCode] - Interner Statuscode vom Webservice (optional)
  /// [statusMessage] - Detaillierte Statusnachricht vom Webservice (optional)
  TokenOrSessionIsMissingException([
    super.message = "",
    super.statusCode = "",
    super.statusMessage = "",
  ]);
}
