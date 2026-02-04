part of 'gsd_restapi.dart';

/// Controller-Klasse für die Steuerung von Datei-Upload-Prozessen
///
/// Diese Klasse ermöglicht es, Datei-Uploads asynchron zu starten und
/// die Upload-ID sofort zu erhalten, während der eigentliche Upload-Prozess
/// im Hintergrund läuft. Der Controller bietet Funktionen zum Abbrechen
/// des Uploads und zum Warten auf das Ergebnis.
///
/// Beispiel-Verwendung:
/// ```dart
/// RestAPIFileUploadController controller = await manager.uploadFileWithController("/path/to/file.pdf");
/// print("Upload ID: ${controller.uploadId}"); // Sofort verfügbar
///
/// try {
///   RestApiResponse result = await controller.result;
///   print("Upload erfolgreich: ${result.data}");
/// } catch (e) {
///   print("Upload fehlgeschlagen: $e");
/// }
/// ```
class RestAPIFileUploadController {
  /// Die eindeutige Upload-ID, die vom Server zugewiesen wurde
  /// Diese ID ist sofort nach der Controller-Erstellung verfügbar
  final String uploadId;

  /// Interner Completer für die asynchrone Verarbeitung des Upload-Ergebnisses
  /// Wird verwendet, um das Future für das Upload-Ergebnis zu steuern
  final Completer<RestApiResponse> _completer = Completer<RestApiResponse>();

  /// Flag, das anzeigt, ob der Upload vom Benutzer abgebrochen wurde
  bool _cancelled = false;

  /// Erstellt einen neuen Upload-Controller mit der angegebenen Upload-ID
  ///
  /// [uploadId] Die eindeutige Upload-ID, die vom Server zugewiesen wurde
  RestAPIFileUploadController(this.uploadId);

  /// Future für das Upload-Ergebnis
  ///
  /// Dieses Future wird abgeschlossen, sobald der Upload erfolgreich beendet wurde
  /// oder mit einem Fehler fehlgeschlagen ist. Das Future kann verwendet werden,
  /// um auf das Ergebnis des Uploads zu warten.
  ///
  /// Returns: [Future<RestApiResponse>] Das Ergebnis des Upload-Prozesses
  Future<RestApiResponse> get result => _completer.future;

  /// Bricht den laufenden Upload ab
  ///
  /// Nach dem Aufruf dieser Methode wird der Upload gestoppt und das result-Future
  /// mit einem "Upload cancelled" Fehler abgeschlossen. Diese Aktion kann nicht
  /// rückgängig gemacht werden.
  ///
  /// Hinweis: Der Upload kann nur abgebrochen werden, solange er noch läuft.
  /// Bereits abgeschlossene Uploads können nicht mehr abgebrochen werden.
  void cancel() {
    _cancelled = true;
    if (!_completer.isCompleted) {
      _completer.completeError("Upload cancelled");
    }
  }

  /// Markiert den Upload als erfolgreich abgeschlossen
  ///
  /// Diese Methode wird intern vom Upload-Manager aufgerufen, wenn der Upload
  /// erfolgreich beendet wurde. Sie schließt das result-Future mit der
  /// Server-Antwort ab.
  ///
  /// [response] Die Server-Antwort nach erfolgreichem Upload
  ///
  /// Hinweis: Diese Methode sollte nur intern verwendet werden und nicht
  /// direkt von Benutzer-Code aufgerufen werden.
  void complete(RestApiResponse response) {
    if (!_cancelled && !_completer.isCompleted) {
      _completer.complete(response);
    }
  }

  /// Markiert den Upload als fehlgeschlagen
  ///
  /// Diese Methode wird intern vom Upload-Manager aufgerufen, wenn der Upload
  /// mit einem Fehler fehlgeschlagen ist. Sie schließt das result-Future mit
  /// dem entsprechenden Fehler ab.
  ///
  /// [error] Der Fehler, der während des Uploads aufgetreten ist
  ///
  /// Hinweis: Diese Methode sollte nur intern verwendet werden und nicht
  /// direkt von Benutzer-Code aufgerufen werden.
  void completeError(dynamic error) {
    if (!_cancelled && !_completer.isCompleted) {
      _completer.completeError(error);
    }
  }
}
