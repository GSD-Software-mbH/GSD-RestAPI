part of '../restapi.dart';

/// Exception für Lizenz-bezogene Fehler
/// 
/// Wird geworfen, wenn der Webservice die Fehlercodes 306 oder 101 zurückgibt,
/// was auf Lizenzprobleme hinweist. Diese Exception tritt auf bei:
/// - Abgelaufener Lizenz
/// - Ungültiger Lizenz
/// - Lizenz-Verletzungen
/// - Überschreitung von Lizenz-Limits
/// - Fehlenden Lizenz-Berechtigungen
/// 
/// Für alle Fehlercodes siehe: https://docs.gsd.pl/restapi/errorCodes/errorCodes/
class LicenseException implements Exception {
  /// Beschreibende Fehlernachricht über das Lizenzproblem
  String message;

  /// Der interne Statuscode vom Webservice (normalerweise "306" oder "101")
  String statusCode;

  /// Die detaillierte Statusnachricht vom Webservice
  String statusMessage;

  /// Erstellt eine neue LicenseException
  /// 
  /// [message] - Beschreibende Fehlernachricht (optional)
  /// [statusCode] - Interner Statuscode vom Webservice (optional)
  /// [statusMessage] - Detaillierte Statusnachricht vom Webservice (optional)
  LicenseException([this.message = "", this.statusCode = "", this.statusMessage = ""]);

  /// String-Darstellung der Exception
  @override
  String toString() {
    return message;
  }
}
