part of '../restapi.dart';

/// Response-Klasse für Datei-Download-Anfragen
/// 
/// Spezialisierte Response-Klasse für den Download von Dateien über die REST-API.
/// Im Gegensatz zu normalen API-Responses enthält diese Klasse die rohen Datei-Bytes
/// anstatt JSON-Daten.
/// 
/// Verwendung:
/// - Datei-Downloads über `/v1/file/{oid}`
/// - Binärdaten (Bilder, Dokumente, etc.)
/// - Direct File Access ohne JSON-Wrapper
class RestApiFileResponse {
  /// HTTP-Response mit den Datei-Daten
  /// 
  /// Enthält die rohen Bytes der Datei im Response-Body sowie
  /// wichtige Header-Informationen wie Content-Type und Content-Length.
  final http.Response _httpResponse;

  /// Erfolgsstatus der Datei-Anfrage
  /// 
  /// true = Datei erfolgreich geladen, false = Fehler aufgetreten
  bool _isOk = false;

  /// Getter für die HTTP-Response
  http.Response get httpResponse => _httpResponse;
  
  /// Getter für den Erfolgsstatus
  bool get isOk => _isOk;

  /// Erstellt eine RestApiFileResponse-Instanz
  /// 
  /// Validiert den HTTP-Statuscode und setzt den Erfolgsstatus.
  /// Datei-Responses werden direkt über HTTP-Statuscodes validiert,
  /// nicht über JSON-basierte Statusinformationen.
  /// 
  /// [_httpResponse] - Die HTTP-Response vom Datei-Endpoint
  /// 
  /// Throws: HttpRequestException wenn Statuscode != 200
  RestApiFileResponse(this._httpResponse) {
    if (httpResponse.statusCode != 200) {
      throw HttpRequestException(
          "HTTPResponseException: ${httpResponse.statusCode} ${httpResponse.reasonPhrase}", 
          httpResponse.statusCode.toString(),
          reasonPhrase: httpResponse.reasonPhrase);

      // Mögliche Erweiterung: Status/InternalStatus/StatusMessage bei 404 extrahieren
    } else {
      _isOk = true;
    }
  }
}
