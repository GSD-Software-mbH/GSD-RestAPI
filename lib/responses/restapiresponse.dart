part of '../restapi.dart';

/// Basisklasse für alle REST-API-Antworten
/// 
/// Diese Klasse verarbeitet HTTP-Antworten von der REST-API und extrahiert
/// Statusinformationen. Sie wirft entsprechende Exceptions basierend auf
/// dem internen Statuscode der API-Antwort.
/// 
/// Unterstützte Statuscodes:
/// - 0: Erfolg
/// - 201: Session ungültig
/// - 204: Token oder Session fehlt
/// - 302: Falsche Benutzerdaten
/// - 306/101: Lizenzprobleme
/// - Andere: Allgemeine Webservice-Fehler
class RestApiResponse {
  /// HTTP-Antwort vom Server
  final http.Response _httpResponse;

  /// Interner Statuscode aus dem 'status.internalStatus' Feld der API-Antwort
  /// 
  /// "0" bedeutet Erfolg, alle anderen Werte sind Fehlercodes.
  String _internalStatus = "0";

  /// Statusnachricht aus dem 'status.statusMessage' Feld der API-Antwort
  /// 
  /// Enthält eine beschreibende Nachricht zum Status der Anfrage.
  String _statusMessage = "";

  /// Kennzeichnet ob die Anfrage erfolgreich war
  /// 
  /// true = Erfolg (internalStatus == "0"), false = Fehler
  bool _isOk = false;

  /// Getter für die rohe HTTP-Antwort
  http.Response get httpResponse => _httpResponse;
  
  /// Getter für den internen Statuscode
  String get internalStatus => _internalStatus;
  
  /// Getter für die Statusnachricht
  String get statusMessage => _statusMessage;
  
  /// Getter für den Erfolgsstatus
  bool get isOk => _isOk;

  /// Erstellt eine RestApiResponse-Instanz basierend auf einer HTTP-Antwort
  /// 
  /// Parst die JSON-Antwort und extrahiert Statusinformationen.
  /// Wirft spezifische Exceptions basierend auf dem internen Statuscode.
  /// 
  /// [_httpResponse] - Die HTTP-Antwort vom Server
  /// 
  /// Throws:
  /// - [HttpRequestException] wenn der HTTP-Statuscode nicht 200 ist
  /// - [FormatException] wenn erforderliche Felder in der Antwort fehlen
  /// - [SessionInvalidException] bei Statuscode 201
  /// - [TokenOrSessionIsMissingException] bei Statuscode 204
  /// - [UserAndPassWrongException] bei Statuscode 302
  /// - [LicenseException] bei Statuscode 306 oder 101
  /// - [WebServiceException] bei anderen Fehlercodes
  RestApiResponse(this._httpResponse) {
    Map<String, dynamic> responseJson;

    try {
      responseJson = jsonDecode(httpResponse.body);
    } catch (e) {
      rethrow;
    }

    if (!responseJson.containsKey("status")) {

      throw HttpRequestException(
          "HTTPResponseException: ${httpResponse.statusCode} ${httpResponse.reasonPhrase}", httpResponse.statusCode as String,
          reasonPhrase: httpResponse.reasonPhrase);
    } else {
      var statusJson = responseJson['status'];
      if (!statusJson.containsKey("internalStatus")) {
        throw FormatException("missing 'status.internalStatus' field in response body", responseJson);
      } else {
        _internalStatus = statusJson['internalStatus'];
      }

      if (!statusJson.containsKey("statusMessage")) {
        throw FormatException("missing 'status.statusMessage' field in response body", responseJson);
      } else {
        _statusMessage = statusJson['statusMessage'];
      }
    }

    if (_internalStatus == "0") {

      _isOk = true;
    } else if (_internalStatus == "201") {
      throw SessionInvalidException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    } else if (_internalStatus == "204") {
      throw TokenOrSessionIsMissingException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    } else if (_internalStatus == "302") {
      throw UserAndPassWrongException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    } else if (_internalStatus == "306" || _internalStatus == "101") {
      throw LicenseException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    } else if (_internalStatus == "341") {
      throw Missing2FATokenException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    } else if (_internalStatus == "342") {
      throw Invalid2FATokenException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    } else {
      throw WebServiceException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    }
  }
}
