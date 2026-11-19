import 'dart:async';

import 'package:gsd_restapi/src/exceptions/gsd_api_exception.dart';
import 'package:meta/meta.dart';

/// Controller-Klasse für die Steuerung von Datei-Upload-Prozessen
///
/// Diese Klasse ermöglicht es, Datei-Uploads asynchron zu starten und
/// die Upload-ID sofort zu erhalten, während der eigentliche Upload-Prozess
/// im Hintergrund läuft. Der Controller bietet Funktionen zum Abbrechen
/// des Uploads und zum Warten auf das Ergebnis.
///
/// Beispiel-Verwendung:
/// ```dart
/// GsdFileUploadController controller = await manager.uploadFileWithController("/path/to/file.pdf");
/// print("Upload ID: ${controller.uploadId}"); // Sofort verfügbar
///
/// try {
///   final Object? data = await controller.result;
///   print("Upload erfolgreich: $data");
/// } on GsdUploadCancelledException {
///   print("Upload abgebrochen");
/// }
/// ```
class GsdFileUploadController {
  /// Erstellt einen neuen Upload-Controller mit der angegebenen Upload-ID
  ///
  /// [uploadId] Die eindeutige Upload-ID, die vom Server zugewiesen wurde
  GsdFileUploadController(this.uploadId);

  /// Die eindeutige Upload-ID, die vom Server zugewiesen wurde
  /// Diese ID ist sofort nach der Controller-Erstellung verfügbar
  final String uploadId;

  /// Interner Completer für die asynchrone Verarbeitung des Upload-Ergebnisses
  /// Wird verwendet, um das Future für das Upload-Ergebnis zu steuern
  final Completer<Object?> _completer = Completer<Object?>();

  /// Flag, das anzeigt, ob der Upload vom Benutzer abgebrochen wurde
  bool _cancelled = false;

  /// Future für das Upload-Ergebnis
  ///
  /// Dieses Future wird abgeschlossen, sobald der Upload erfolgreich beendet
  /// wurde oder mit einem Fehler fehlgeschlagen ist. Das Future kann verwendet
  /// werden, um auf das Ergebnis des Uploads zu warten.
  ///
  /// Liefert `data` der letzten Antwort des Uploads.
  Future<Object?> get result => _completer.future;

  /// Bricht den laufenden Upload ab
  ///
  /// Das result-Future endet danach mit [GsdUploadCancelledException]. Diese
  /// Aktion kann nicht rückgängig gemacht werden.
  ///
  /// Der Abbruch gilt nur bis zum Start des letzten Schritts (PATCH, legt das
  /// Dokumentobjekt an); danach bewirkt er nichts mehr, und result liefert
  /// den Erfolg. Bis dahin ist er "best effort": Bereits gesendete Bytes
  /// kommen beim Server an.
  void cancel() {
    _cancelled = true;
    if (!_completer.isCompleted) {
      _completer.completeError(const GsdUploadCancelledException());
    }
  }

  /// Markiert den Upload als erfolgreich abgeschlossen
  ///
  /// Diese Methode wird intern vom Upload-Manager aufgerufen, wenn der Upload
  /// erfolgreich beendet wurde. Sie schließt das result-Future mit der
  /// Server-Antwort ab.
  ///
  /// [data] `data` der Server-Antwort nach erfolgreichem Upload
  ///
  /// Hinweis: Diese Methode sollte nur intern verwendet werden und nicht
  /// direkt von Benutzer-Code aufgerufen werden.
  @internal
  void complete(Object? data) {
    if (!_cancelled && !_completer.isCompleted) {
      _completer.complete(data);
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
  @internal
  void completeError(dynamic error) {
    if (!_cancelled && !_completer.isCompleted) {
      _completer.completeError(error as Object);
    }
  }
}
