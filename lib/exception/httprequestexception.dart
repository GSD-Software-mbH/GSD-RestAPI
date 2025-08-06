part of '../gsd_restapi.dart';

/// Exception für HTTP-Request-Fehler
/// 
/// Wird geworfen, wenn eine HTTP-Anfrage einen Fehlercode zurückgibt
/// und der Webservice daher nicht erreicht werden konnte.
/// 
/// Diese Exception tritt auf bei:
/// - Netzwerkproblemen
/// - Server nicht erreichbar
/// - HTTP-Statuscodes != 200
/// - Timeout-Problemen
class HttpRequestException implements Exception {
  /// Beschreibende Fehlernachricht
  String message;

  /// Der tatsächliche Statuscode aus der HTTP-Antwort
  /// 
  /// Beispiele: "404", "500", "503"
  String statusCode;

  /// Die Statusnachricht aus der HTTP-Antwort
  /// 
  /// Beispiele: "Not Found", "Internal Server Error", "Service Unavailable"
  String? reasonPhrase;

  /// Erstellt eine neue HttpRequestException
  /// 
  /// [message] - Beschreibende Fehlernachricht
  /// [statusCode] - HTTP-Statuscode der fehlerhaften Antwort
  /// [reasonPhrase] - Optional: HTTP-Statusnachricht (Standard: "")
  HttpRequestException(this.message, this.statusCode,
      {this.reasonPhrase = ""});
}
