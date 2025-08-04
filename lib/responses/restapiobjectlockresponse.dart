part of '../restapi.dart';

/// Response-Klasse für Objekt-Sperr-Anfragen
/// 
/// Diese Klasse wird verwendet, um den Sperrstatus von Objekten in der
/// REST-API zu verwalten. Objekt-Sperren verhindern gleichzeitige
/// Bearbeitung durch mehrere Benutzer.
/// 
/// Verwendung:
/// - Prüfung ob ein Objekt bereits gesperrt ist
/// - Abrufen von Sperr-Informationen und -Nachrichten
/// - Konflikt-Management bei gleichzeitiger Bearbeitung
/// - Multi-User-Synchronisation
class RestApiObjectLockResponse extends RestApiResponse {
  /// Gibt an, ob das Objekt aktuell gesperrt ist
  /// 
  /// true = Objekt ist gesperrt (nicht bearbeitbar)
  /// false = Objekt ist frei verfügbar
  bool isLocked = false;
  
  /// Liste der Nachrichten bezüglich der Objektsperre
  /// 
  /// Kann Informationen enthalten über:
  /// - Wer das Objekt gesperrt hat
  /// - Seit wann die Sperre aktiv ist
  /// - Grund der Sperre
  /// - Weitere relevante Sperr-Details
  List<String> messages = [];

  /// Erstellt eine RestApiObjectLockResponse-Instanz
  /// 
  /// Parst die HTTP-Response und extrahiert Sperrstatus und Nachrichten.
  /// 
  /// [_httpResponse] - Die HTTP-Response vom Object-Lock-Endpoint
  /// 
  /// Throws: FormatException wenn 'data' oder 'data.isLocked' fehlen
  RestApiObjectLockResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {
        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];
        if (!dataJson.containsKey("isLocked")) {
          throw const FormatException("missing 'data.isLocked' field in response body");
        } else {
          isLocked = dataJson['isLocked'];
        }

        // Extrahiere Sperr-Nachrichten
        dynamic messagesJson = dataJson["messages"];
        dynamic currentMessage;

        if(messagesJson == null) {
          return;
        }

        for (var i = 0; i < messagesJson.length; i++) {
          currentMessage = messagesJson[i];

          if(currentMessage != null) {
            messages.add(currentMessage);
          }
        }
      }
    }
  }
}
