part of '../gsd_restapi.dart';

/// Exception für allgemeine Webservice-Fehler
///
/// Wird als Fallback-Exception für alle anderen Webservice-Fehlercodes geworfen,
/// die nicht durch spezifische Exception-Klassen abgedeckt sind.
///
/// Diese Exception tritt auf bei:
/// - Unbekannten oder neuen Fehlercodes
/// - Allgemeinen Server-Fehlern
/// - Unerwarteten API-Antworten
/// - Temporären Service-Problemen
/// - Nicht kategorisierten Fehlern
///
/// Für alle Fehlercodes siehe: https://docs.gsd.pl/restapi/errorCodes/errorCodes/
class WebServiceException implements Exception {
  /// Beschreibende Fehlernachricht über den Webservice-Fehler
  String message;

  /// Der interne Statuscode vom Webservice
  String statusCode;

  /// Die detaillierte Statusnachricht vom Webservice
  String statusMessage;

  /// Erstellt eine neue WebServiceException
  ///
  /// [message] - Beschreibende Fehlernachricht (optional)
  /// [statusCode] - Interner Statuscode vom Webservice (optional)
  /// [statusMessage] - Detaillierte Statusnachricht vom Webservice (optional)
  WebServiceException([
    this.message = "",
    this.statusCode = "",
    this.statusMessage = "",
  ]);

  /// String-Darstellung der Exception im Format "StatusCode: StatusMessage"
  @override
  String toString() {
    return "$statusCode: $statusMessage";
  }
}
