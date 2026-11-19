import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_file_download.dart';
import 'package:gsd_restapi/src/models/gsd_file_upload_controller.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/gsd_upload_file.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/binary_response_policy.dart';
import 'package:gsd_restapi/src/runtime/transport/upload_executor.dart';
import 'package:gsd_restapi/src/v1/v1_requester.dart';
import 'package:meta/meta.dart';

/// Native Dokument-, Datei- und Uploadoperationen der V1-Fassade.
class GsdV1DocumentsApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1DocumentsApi.internal(this._runtime, this._uploadExecutor);
  late final V1Requester _requests = V1Requester(_runtime, 'documents');
  static const FileDownloadResponsePolicy _fileResponsePolicy =
      FileDownloadResponsePolicy();
  static const NullableBinaryBytesResponsePolicy _previewResponsePolicy =
      NullableBinaryBytesResponsePolicy();

  final ApiRuntime _runtime;
  final UploadExecutor _uploadExecutor;

  /// Lädt eine Datei anhand ihrer Objekt-ID herunter
  ///
  /// Ruft den Dateiinhalt und die Metadaten einer gespeicherten Datei ab.
  /// Die Methode prüft automatisch die Session und lädt dann die vollständige
  /// Datei.
  ///
  /// [oid] - Die eindeutige Objekt-ID der Datei
  ///
  /// Returns: [GsdFileDownload] mit den unveränderten Bytes und den
  /// Response-Headern (Binärantwort, umgeht die Response-Entschlüsselung)
  ///
  /// Throws: `GsdHttpException` bei einem Statuscode != 200
  ///
  /// Beispiel:
  /// ```dart
  /// try {
  ///   final GsdFileDownload file =
  ///       await api.v1.documents.getFile("file-oid-12345");
  ///   Uint8List fileData = file.bytes;
  ///   String? mimeType = file.headers['content-type'];
  ///   // Datei speichern oder verarbeiten
  /// } catch (e) {
  ///   print("Datei-Download fehlgeschlagen: $e");
  /// }
  /// ```
  Future<GsdFileDownload> getFile(String oid) {
    return _runtime.execute(
      ApiRequest<GsdFileDownload>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v1,
        path: '/file/$oid',
        authentication: AuthenticationPolicy.session,
        responsePolicy: _fileResponsePolicy,
        operationId: 'v1.documents.getFile',
      ),
    );
  }

  /// Generiert eine Vorschau-Darstellung eines Objekts
  ///
  /// Erstellt eine Vorschau (Thumbnail) für Dokumente, Bilder oder andere
  /// Objekte in der angegebenen Größe und Qualität.
  ///
  /// [objectOid] - Die Objekt-ID des Elements für die Vorschau
  /// [parameters] - Format-Parameter (z.B. "200x150" für Größe, "jpg" für
  ///   Format)
  /// [page] - Seitenzahl bei mehrseitigen Dokumenten (Standard: 0)
  /// [keepRatio] - Seitenverhältnis beibehalten (Standard: true)
  ///
  /// Returns: [Uint8List] mit den Bilddaten der Vorschau oder null bei Fehlern
  ///
  /// Beispiel:
  /// ```dart
  /// Uint8List? previewData = await api.v1.documents.getPreview(
  ///   "document-oid-12345",
  ///   "300x200.jpg",
  ///   page: 1,
  ///   keepRatio: true
  /// );
  /// if (previewData != null) {
  ///   // Vorschau anzeigen
  ///   Image.memory(previewData);
  /// }
  /// ```
  Future<Uint8List?> getPreview(
    String objectOid,
    String parameters, {
    int page = 0,
    bool keepRatio = true,
  }) {
    final path = keepRatio
        ? '/preview/$parameters/keep-ratio/$objectOid/$page'
        : '/preview/$parameters//$objectOid/$page';
    return _runtime.execute(
      ApiRequest<Uint8List?>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v1,
        path: path,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _previewResponsePolicy,
        operationId: 'v1.documents.getPreview',
      ),
    );
  }

  /// Lädt eine Datei auf den Server hoch
  ///
  /// Überträgt eine lokale Datei oder Web-Datei auf den Server und erstellt
  /// optional ein Dokumentobjekt in der Datenbank.
  ///
  /// [file] - GsdUploadFile-Objekt mit Dateipfad oder Bytes
  /// [replaceOID] - OID eines bestehenden Dokuments zum Ersetzen
  /// [fetchToObject] - Dokument-Objekt nach Upload erstellen (Standard: true)
  ///
  /// Returns: `data` der letzten Antwort, mit `fetchToObject` die des
  /// Dokumentobjekts (etwa `objectId`)
  ///
  /// Der Upload-Prozess erfolgt in drei Schritten:
  /// 1. Upload-ID vom Server anfordern
  /// 2. Datei mit Multipart-Request hochladen
  /// 3. Dokument-Objekt erstellen (falls fetchToObject=true)
  ///
  /// Beispiel:
  /// ```dart
  /// GsdUploadFile file = GsdUploadFile.fromPath("/path/to/document.pdf");
  /// final data = await api.v1.documents.uploadFile(
  ///   file,
  ///   fetchToObject: true
  /// ) as Map<String, Object?>;
  /// String documentId = data['objectId'] as String;
  /// ```
  ///
  /// Muss der Multipart-Schritt nach einer abgelaufenen Session wiederholt
  /// werden, sendet er die Datei erneut.
  Future<Object?> uploadFile(
    GsdUploadFile file, {
    String replaceOID = '',
    bool fetchToObject = true,
  }) {
    return _uploadExecutor.uploadFile(
      file,
      replaceOID: replaceOID,
      fetchToObject: fetchToObject,
    );
  }

  /// Lädt eine Datei mit Upload-Controller hoch
  ///
  /// Überträgt eine Datei asynchron auf den Server und erstellt einen
  /// Controller zur Überwachung des Upload-Fortschritts. Unterstützt sowohl
  /// lokale Dateien als auch Web-Uploads mit Fehlerbehandlung und
  /// Status-Callbacks.
  ///
  /// [file] - GsdUploadFile-Objekt mit Dateipfad oder Bytes
  /// [replaceOID] - OID eines bestehenden Dokuments zum Ersetzen (optional)
  /// [fetchToObject] - Dokument-Objekt nach Upload erstellen (Standard: true)
  ///
  /// Returns: [GsdFileUploadController] zur Überwachung des Upload-Status
  ///
  /// Der Upload-Prozess erfolgt in folgenden Schritten:
  /// 1. Upload-ID vom Server anfordern
  /// 2. Controller erstellen und zu aktiven Uploads hinzufügen
  /// 3. Asynchronen Upload mit Multipart-Request durchführen
  /// 4. Optional: Dokument-Objekt in der Datenbank erstellen
  /// 5. Controller mit Ergebnis oder Fehler abschließen
  ///
  /// Der Controller bietet:
  /// - `result` mit `data` der letzten Antwort (wie [uploadFile])
  /// - Automatische Fehlerbehandlung und -weiterleitung
  /// - Tracking aktiver Uploads zur Vermeidung von Duplikaten
  ///
  /// Beispiel:
  /// ```dart
  /// GsdUploadFile file = GsdUploadFile.fromPath("/path/to/document.pdf");
  /// GsdFileUploadController controller =
  ///     await api.v1.documents.uploadFileWithController(
  ///   file,
  ///   fetchToObject: true
  /// );
  ///
  /// try {
  ///   final data = await controller.result as Map<String, Object?>;
  ///   print("Upload erfolgreich: ${data['objectId']}");
  /// } on GsdUploadCancelledException {
  ///   print("Upload abgebrochen");
  /// }
  /// ```
  ///
  /// Muss der Multipart-Schritt nach einer abgelaufenen Session wiederholt
  /// werden, sendet er die Datei erneut.
  Future<GsdFileUploadController> uploadFileWithController(
    GsdUploadFile file, {
    String replaceOID = '',
    bool fetchToObject = true,
  }) {
    return _uploadExecutor.uploadFileWithController(
      file,
      replaceOID: replaceOID,
      fetchToObject: fetchToObject,
    );
  }

  /// Ruft Informationen über eine hochgeladene Datei ab, einschließlich Größe
  /// und MD5-Hash
  ///
  /// Diese Methode ruft Metadaten für eine Datei ab, die mit der angegebenen
  /// Upload-ID auf den Server hochgeladen wird. Die Antwort enthält die
  /// Dateigröße in Bytes und den MD5-Hash zur Verifikation.
  ///
  /// [uploadID] - Die eindeutige Kennung der hochgeladenen Datei
  ///
  /// Returns: `data` der Antwort mit Datei-Metadaten und Größeninformationen
  ///
  /// Die Antwort enthält:
  /// - Dateigröße in Bytes
  /// - MD5-Hash zur Integritätsprüfung
  /// - Status-Informationen über den Upload
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.documents.getUploadFile("upload-123")
  ///     as Map<String, Object?>;
  /// int fileSize = data['size'] as int;
  /// String md5Hash = data['hash'] as String;
  /// print("Dateigröße: $fileSize Bytes, Hash: $md5Hash");
  /// ```
  Future<Object?> getUploadFile(String uploadID) => _requests.execute(
    method: GsdHttpMethod.get,
    path: '/uploadFile/$uploadID',
    operation: 'getUploadFile',
  );

  /// Markiert Dokumente als gelesen oder ungelesen
  ///
  /// Ändert den Lesestatus von Dokumenten für den aktuellen Benutzer.
  /// Hilfreich für die Verwaltung von Benachrichtigungen und To-Do-Listen.
  ///
  /// [ids] - Liste von Dokument-OIDs oder UUIDs
  /// [read] - true = als gelesen markieren, false = als ungelesen (Standard:
  ///   true)
  ///
  /// Returns: `data` der Antwort mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// // Dokumente als gelesen markieren
  /// final data = await api.v1.documents.putDocsRead(
  ///   ["doc-123", "doc-456"],
  ///   read: true
  /// );
  ///
  /// // Dokumente als ungelesen markieren
  /// await api.v1.documents.putDocsRead(["doc-789"], read: false);
  /// ```
  Future<Object?> putDocsRead(List<String> ids, {bool read = true}) {
    return _requests.execute(
      method: GsdHttpMethod.put,
      path: '/docs/read',
      operation: 'putDocsRead',
      body: jsonEncode(<String, dynamic>{'read': read, 'ids': ids}),
    );
  }

  /// Markiert Dokumente als nicht mehr neu
  ///
  /// Entfernt Dokumente aus der Liste der neuen Dokumente für den aktuellen
  /// Benutzer.
  /// Wird verwendet, um die "Neu"-Kennzeichnung von Dokumenten zu entfernen.
  ///
  /// [ids] - Liste von Dokument-OIDs oder UUIDs
  ///
  /// Returns: `data` der Antwort mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.documents.putDocsNotNew(
  ///   ["doc-123", "doc-456", "doc-789"]
  /// );
  /// print("Dokumente als 'nicht neu' markiert");
  /// ```
  Future<Object?> putDocsNotNew(List<String> ids) {
    return _requests.execute(
      method: GsdHttpMethod.put,
      path: '/docs/removeDocFromNewDocuments',
      operation: 'putDocsNotNew',
      body: jsonEncode(<String, dynamic>{'ids': ids}),
    );
  }

  /// Verwaltet die Objekthistorie des Benutzers
  ///
  /// Fügt Objekte zur Benutzerhistorie hinzu oder löscht komplette
  /// Klassenhistorien. Die Historie wird für schnellen Zugriff auf kürzlich
  /// verwendete Objekte verwendet.
  ///
  /// [ids] - Liste von Objekt-OIDs oder UUIDs
  /// [action] - "add" zum Hinzufügen, "remove" zum Löschen (Standard: "add")
  /// [className] - Klassenname zum Löschen der gesamten Klassenhistorie
  ///
  /// Returns: `data` der Antwort mit dem Aktualisierungsstatus
  ///
  /// Beispiele:
  /// ```dart
  /// // Objekte zur Historie hinzufügen
  /// await api.v1.documents.putDocsHistory(["obj-123", "obj-456"]);
  ///
  /// // Komplette Vorgangs-Historie löschen
  /// await api.v1.documents.putDocsHistory(
  ///   ["dummy-id"],
  ///   action: "remove",
  ///   className: "Vorgang"
  /// );
  /// ```
  Future<Object?> putDocsHistory(
    List<String> ids, {
    String action = 'add',
    String className = '',
  }) {
    final body = <String, dynamic>{
      'action': action,
      'ids': ids,
    };
    if (className.isNotEmpty) {
      body['className'] = className;
    }
    return _requests.execute(
      method: GsdHttpMethod.put,
      path: '/docs/history',
      operation: 'putDocsHistory',
      body: jsonEncode(body),
    );
  }

  /// Ruft Dokumentpfade für ein Objekt ab
  ///
  /// Lädt die Pfad-Informationen und Speicherort-Details für ein
  /// spezifisches Dokument oder Objekt.
  ///
  /// [oid] - Die Objekt-ID des Dokuments
  /// [extended] - Wenn true, werden erweiterte Pfad-Informationen zurückgegeben
  ///   (Standard: false)
  ///
  /// Returns: `data` der Antwort mit Pfad-Informationen und Metadaten
  ///
  /// Beispiel:
  /// ```dart
  /// final paths = await api.v1.documents.getDocumentPaths(
  ///   "doc-12345",
  ///   extended: true,
  /// ) as Map<String, Object?>;
  /// ```
  Future<Object?> getDocumentPaths(
    String oid, {
    bool extended = false,
  }) {
    return _requests.execute(
      method: GsdHttpMethod.get,
      path: '/docs/documentPaths/$oid',
      operation: 'getDocumentPaths',
      queryParameters: <String, String>{'extended': extended.toString()},
    );
  }
}
