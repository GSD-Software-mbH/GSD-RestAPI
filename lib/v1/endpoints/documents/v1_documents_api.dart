part of '../../../docuframe_api.dart';

/// Native Dokument-, Datei- und Uploadoperationen der V1-Fassade.
class V1DocumentsApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();
  static const BinaryLegacyResponsePolicy<RestApiFileResponse>
  _fileResponsePolicy = BinaryLegacyResponsePolicy<RestApiFileResponse>(
    RestApiFileResponse.new,
  );
  static const NullableBinaryBytesResponsePolicy _previewResponsePolicy =
      NullableBinaryBytesResponsePolicy();

  final ApiRuntime _runtime;
  final UploadExecutor _uploadExecutor;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1DocumentsApi.internal(this._runtime, this._uploadExecutor);

  /// Lädt eine Datei anhand ihrer Objekt-ID herunter
  ///
  /// Ruft den Dateiinhalt und die Metadaten einer gespeicherten Datei ab.
  /// Die Methode prüft automatisch die Session und lädt dann die vollständige Datei.
  ///
  /// [oid] - Die eindeutige Objekt-ID der Datei
  ///
  /// Returns: [RestApiFileResponse] mit Dateiinhalt, MIME-Type und Metadaten
  ///
  /// Throws: Exception bei Netzwerkfehlern oder ungültiger OID
  ///
  /// Beispiel:
  /// ```dart
  /// try {
  ///   RestApiFileResponse response = await api.v1.documents.getFile("file-oid-12345");
  ///   if (response.isOk) {
  ///     Uint8List fileData = response.data;
  ///     String fileName = response.fileName;
  ///     String mimeType = response.mimeType;
  ///     // Datei speichern oder verarbeiten
  ///   }
  /// } catch (e) {
  ///   print("Datei-Download fehlgeschlagen: $e");
  /// }
  /// ```
  Future<RestApiFileResponse> getFile(String oid) {
    return _runtime.execute(
      ApiRequest<RestApiFileResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v1,
        path: '/file/$oid',
        authentication: AuthenticationPolicy.session,
        responsePolicy: _fileResponsePolicy,
        operationId: 'v1.documents.getFile',
      ),
    );
  }

  /// Generiert eine Vorschau-Darstellung eines Objekts
  ///
  /// Erstellt eine Vorschau (Thumbnail) für Dokumente, Bilder oder andere Objekte
  /// in der angegebenen Größe und Qualität.
  ///
  /// [objectOid] - Die Objekt-ID des Elements für die Vorschau
  /// [parameters] - Format-Parameter (z.B. "200x150" für Größe, "jpg" für Format)
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
    final String path = keepRatio
        ? '/preview/$parameters/keep-ratio/$objectOid/$page'
        : '/preview/$parameters//$objectOid/$page';
    return _runtime.execute(
      ApiRequest<Uint8List?>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v1,
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
  /// [file] - RestApiUploadFile-Objekt mit Dateipfad oder Bytes
  /// [replaceOID] - OID eines bestehenden Dokuments zum Ersetzen
  /// [patch] - Patch-Modus verwenden (Standard: true)
  /// [fetchToObject] - Dokument-Objekt nach Upload erstellen (Standard: true)
  ///
  /// Returns: [RestApiResponse] mit Upload-Status und Dokument-ID
  ///
  /// Der Upload-Prozess erfolgt in drei Schritten:
  /// 1. Upload-ID vom Server anfordern
  /// 2. Datei mit Multipart-Request hochladen
  /// 3. Dokument-Objekt erstellen (falls fetchToObject=true)
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiUploadFile file = RestApiUploadFile.fromPath("/path/to/document.pdf");
  /// RestApiResponse response = await api.v1.documents.uploadFile(
  ///   file,
  ///   fetchToObject: true
  /// );
  /// if (response.isOk) {
  ///   String documentId = response.data['objectId'];
  /// }
  /// ```
  Future<RestApiResponse> uploadFile(
    RestApiUploadFile file, {
    String replaceOID = '',
    bool patch = true,
    bool fetchToObject = true,
  }) {
    return _uploadExecutor.uploadFile(
      file,
      replaceOID: replaceOID,
      patch: patch,
      fetchToObject: fetchToObject,
    );
  }

  /// Lädt eine Datei mit Upload-Controller hoch
  ///
  /// Überträgt eine Datei asynchron auf den Server und erstellt einen Controller
  /// zur Überwachung des Upload-Fortschritts. Unterstützt sowohl lokale Dateien
  /// als auch Web-Uploads mit Fehlerbehandlung und Status-Callbacks.
  ///
  /// [file] - RestApiUploadFile-Objekt mit Dateipfad oder Bytes
  /// [replaceOID] - OID eines bestehenden Dokuments zum Ersetzen (optional)
  /// [patch] - Patch-Modus verwenden (Standard: true)
  /// [fetchToObject] - Dokument-Objekt nach Upload erstellen (Standard: true)
  ///
  /// Returns: [RestAPIFileUploadController] zur Überwachung des Upload-Status
  ///
  /// Der Upload-Prozess erfolgt in folgenden Schritten:
  /// 1. Upload-ID vom Server anfordern
  /// 2. Controller erstellen und zu aktiven Uploads hinzufügen
  /// 3. Asynchronen Upload mit Multipart-Request durchführen
  /// 4. Optional: Dokument-Objekt in der Datenbank erstellen
  /// 5. Controller mit Ergebnis oder Fehler abschließen
  ///
  /// Der Controller bietet:
  /// - Future für asynchrone Ergebnis-Behandlung
  /// - Automatische Fehlerbehandlung und -weiterleitung
  /// - Tracking aktiver Uploads zur Vermeidung von Duplikaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiUploadFile file = RestApiUploadFile.fromPath("/path/to/document.pdf");
  /// RestAPIFileUploadController controller = await api.v1.documents.uploadFileWithController(
  ///   file,
  ///   fetchToObject: true
  /// );
  ///
  /// // Erfolgsfall behandeln
  /// controller.future.then((response) {
  ///   if (response.isOk) {
  ///     String documentId = response.data['objectId'];
  ///     print("Upload erfolgreich: $documentId");
  ///   }
  /// }).catchError((error) {
  ///   print("Upload fehlgeschlagen: $error");
  /// });
  /// ```
  Future<RestAPIFileUploadController> uploadFileWithController(
    RestApiUploadFile file, {
    String replaceOID = '',
    bool patch = true,
    bool fetchToObject = true,
    dynamic out,
  }) {
    return _uploadExecutor.uploadFileWithController(
      file,
      replaceOID: replaceOID,
      patch: patch,
      fetchToObject: fetchToObject,
    );
  }

  /// Ruft Informationen über eine hochgeladene Datei ab, einschließlich Größe und MD5-Hash
  ///
  /// Diese Methode ruft Metadaten für eine Datei ab, die mit der angegebenen Upload-ID
  /// auf den Server hochgeladen wird. Die Antwort enthält die Dateigröße in Bytes
  /// und den MD5-Hash zur Verifikation.
  ///
  /// [uploadID] - Die eindeutige Kennung der hochgeladenen Datei
  ///
  /// Returns: [RestApiResponse] mit Datei-Metadaten und Größeninformationen
  ///
  /// Die Antwort enthält:
  /// - Dateigröße in Bytes
  /// - MD5-Hash zur Integritätsprüfung
  /// - Status-Informationen über den Upload
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse restApiResponse = await api.v1.documents.getUploadFile("upload-123");
  /// if (restApiResponse.isOk) {
  ///   int fileSize = restApiResponse.httpResponse.body['data']['size'];
  ///   String md5Hash = restApiResponse.httpResponse.body['data']['hash'];
  ///   print("Dateigröße: $fileSize Bytes, Hash: $md5Hash");
  /// }
  /// ```
  Future<RestApiResponse> getUploadFile(String uploadID) =>
      _execute(ApiHttpMethod.get, '/uploadFile/$uploadID', 'getUploadFile');

  /// Markiert Dokumente als gelesen oder ungelesen
  ///
  /// Ändert den Lesestatus von Dokumenten für den aktuellen Benutzer.
  /// Hilfreich für die Verwaltung von Benachrichtigungen und To-Do-Listen.
  ///
  /// [ids] - Liste von Dokument-OIDs oder UUIDs
  /// [read] - true = als gelesen markieren, false = als ungelesen (Standard: true)
  ///
  /// Returns: [RestApiResponse] mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// // Dokumente als gelesen markieren
  /// RestApiResponse response = await api.v1.documents.putDocsRead(
  ///   ["doc-123", "doc-456"],
  ///   read: true
  /// );
  ///
  /// // Dokumente als ungelesen markieren
  /// await api.v1.documents.putDocsRead(["doc-789"], read: false);
  /// ```
  Future<RestApiResponse> putDocsRead(List<String> ids, {bool read = true}) {
    return _execute(
      ApiHttpMethod.put,
      '/docs/read',
      'putDocsRead',
      body: jsonEncode(<String, dynamic>{'read': read, 'ids': ids}),
    );
  }

  /// Markiert Dokumente als nicht mehr neu
  ///
  /// Entfernt Dokumente aus der Liste der neuen Dokumente für den aktuellen Benutzer.
  /// Wird verwendet, um die "Neu"-Kennzeichnung von Dokumenten zu entfernen.
  ///
  /// [ids] - Liste von Dokument-OIDs oder UUIDs
  ///
  /// Returns: [RestApiResponse] mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.documents.putDocsNotNew(
  ///   ["doc-123", "doc-456", "doc-789"]
  /// );
  /// if (response.isOk) {
  ///   print("Dokumente als 'nicht neu' markiert");
  /// }
  /// ```
  Future<RestApiResponse> putDocsNotNew(List<String> ids) {
    return _execute(
      ApiHttpMethod.put,
      '/docs/removeDocFromNewDocuments',
      'putDocsNotNew',
      body: jsonEncode(<String, dynamic>{'ids': ids}),
    );
  }

  /// Verwaltet die Objekthistorie des Benutzers
  ///
  /// Fügt Objekte zur Benutzerhistorie hinzu oder löscht komplette Klassenhistorien.
  /// Die Historie wird für schnellen Zugriff auf kürzlich verwendete Objekte verwendet.
  ///
  /// [ids] - Liste von Objekt-OIDs oder UUIDs
  /// [action] - "add" zum Hinzufügen, "remove" zum Löschen (Standard: "add")
  /// [className] - Klassenname zum Löschen der gesamten Klassenhistorie
  ///
  /// Returns: [RestApiResponse] mit dem Aktualisierungsstatus
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
  Future<RestApiResponse> putDocsHistory(
    List<String> ids, {
    String action = 'add',
    String className = '',
  }) {
    final Map<String, dynamic> body = <String, dynamic>{
      'action': action,
      'ids': ids,
    };
    if (className.isNotEmpty) {
      body['className'] = className;
    }
    return _execute(
      ApiHttpMethod.put,
      '/docs/history',
      'putDocsHistory',
      body: jsonEncode(body),
    );
  }

  /// Ruft Dokumentpfade für ein Objekt ab
  ///
  /// Lädt die Pfad-Informationen und Speicherort-Details für ein
  /// spezifisches Dokument oder Objekt.
  ///
  /// [oid] - Die Objekt-ID des Dokuments
  /// [extended] - Wenn true, werden erweiterte Pfad-Informationen zurückgegeben (Standard: false)
  ///
  /// Returns: [RestApiResponse] mit Pfad-Informationen und Metadaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.documents.getDocumentPaths("doc-12345", extended: true);
  /// if (response.isOk) {
  ///   Map paths = response.data;
  /// }
  /// ```
  Future<RestApiResponse> getDocumentPaths(
    String oid, {
    bool extended = false,
  }) {
    return _execute(
      ApiHttpMethod.get,
      '/docs/documentPaths/$oid',
      'getDocumentPaths',
      queryParameters: <String, String>{'extended': extended.toString()},
    );
  }

  Future<RestApiResponse> _execute(
    ApiHttpMethod method,
    String path,
    String operation, {
    Map<String, String>? queryParameters,
    String? body,
  }) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: method,
        version: ApiVersion.v1,
        path: path,
        queryParameters: queryParameters,
        body: body,
        authentication: AuthenticationPolicy.session,
        deduplication: method == ApiHttpMethod.get
            ? DeduplicationPolicy.enabled
            : DeduplicationPolicy.disabled,
        responsePolicy: _responsePolicy,
        operationId: 'v1.documents.$operation',
      ),
    );
  }
}
