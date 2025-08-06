part of '../gsd_restapi.dart';

/// Response-Klasse für Benutzer-Systemeinstellungen
/// 
/// Diese Klasse enthält die benutzerdefinierten Systemeinstellungen,
/// die das Verhalten der Anwendung für einen spezifischen Benutzer steuern.
/// 
/// Verwendung:
/// - Benutzereinstellungen nach dem Login laden
/// - UI-Verhalten basierend auf Einstellungen anpassen
/// - Automatisierung und Standard-Verhalten konfigurieren
/// - Berechtigungen und Rechte-Management
class RestApiUserSystemSettingsResponse extends RestApiResponse {
  /// Automatisches Markieren von Dokumenten als gelesen beim Öffnen
  /// 
  /// true = Dokumente werden automatisch als gelesen markiert
  /// false = Manuelle Kennzeichnung erforderlich
  bool autoDocReadOnOpen = false;
  
  /// Keine Rückfrage beim Einfügen neuer Dokumente in Benutzerordner
  /// 
  /// true = Automatisches Einfügen ohne Bestätigung
  /// false = Bestätigungsaufforderung anzeigen
  bool noPromptInsertNewDocsUserFolders = false;
  
  /// Keine Rückfrage beim Einfügen neuer Dokumente in globale Ordner
  /// 
  /// true = Automatisches Einfügen ohne Bestätigung
  /// false = Bestätigungsaufforderung anzeigen
  bool noPromptInsertNewDocsGlobalFolders = false;
  
  /// Standard-Erinnerungszeit für Termine
  /// 
  /// Definiert, wie lange vor einem Termin die Erinnerung standardmäßig
  /// eingestellt werden soll (z.B. 5 Minuten vorher).
  ISODuration dateDefaultReminderTimeSpan = ISODuration(minute: 5);
  
  /// Benutzerrechte als Bitmaske
  /// 
  /// Numerischer Wert, der die verschiedenen Berechtigungen des Benutzers
  /// als Bitmaske codiert. Einzelne Rechte können durch Bit-Operationen
  /// überprüft werden.
  int userRights = 0;
  
  /// Anzahl der nächsten neuen Dokumente
  /// 
  /// Gibt an, wie viele neue Dokumente für diesen Benutzer verfügbar sind
  /// oder als nächstes verarbeitet werden sollten.
  int nextNewDocumentsCount = 0;

  /// Erstellt eine RestApiUserSystemSettingsResponse-Instanz
  /// 
  /// Parst die HTTP-Response und extrahiert alle Benutzereinstellungen.
  /// 
  /// [_httpResponse] - Die HTTP-Response vom UserSystemSettings-Endpoint
  /// 
  /// Throws: FormatException wenn 'data' fehlt
  RestApiUserSystemSettingsResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {
        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];

        autoDocReadOnOpen = dataJson['autoDocReadOnOpen'] ?? false;
        noPromptInsertNewDocsUserFolders = dataJson['noPromptInsertNewDocsUserFolders'] ?? false;
        noPromptInsertNewDocsGlobalFolders = dataJson['noPromptInsertNewDocsGlobalFolders'] ?? false;

        // Parse ISO-Duration für Erinnerungszeit
        if(dataJson['dateDefaultReminderTimeSpan'] != null) {
          dateDefaultReminderTimeSpan = ISODurationConverter().parseString(
            isoDurationString: dataJson['dateDefaultReminderTimeSpan']
          );
        }

        userRights = dataJson['userRights'] ?? 0;
        nextNewDocumentsCount = dataJson['nextNewDocumentsCount'] ?? 0;
      }
    }
  }
}
