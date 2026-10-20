part of '../../../docuframe_api.dart';

/// Native Ordneroperationen der V1-Fassade.
class V1FoldersApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1FoldersApi.internal(this._runtime);

  /// Ruft Ordner-Inhalte nach Ordner-Typ ab
  ///
  /// Lädt alle Dokumente und Unterordner eines bestimmten Ordner-Typs
  /// mit optionaler Paginierung und Suchfunktionalität.
  ///
  /// [folderType] - Der Typ des Ordners (z.B. "Eingang", "Postausgang", "Entwürfe")
  /// [reverseOrder] - Umgekehrte Sortierreihenfolge (Standard: false)
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Elemente pro Seite (Standard: aus Konfiguration)
  /// [query] - Suchtext zum Filtern der Ergebnisse
  ///
  /// Returns: [RestApiResponse] mit Ordner-Inhalten und Metadaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.folders.getFolderByType(
  ///   "Eingang",
  ///   page: 1,
  ///   perPage: 20,
  ///   query: "wichtig"
  /// );
  /// ```
  Future<RestApiResponse> getFolderByType(
    String folderType, {
    bool reverseOrder = false,
    int page = 0,
    int? perPage,
    String query = '',
  }) {
    final Map<String, String> parameters = <String, String>{};
    if (reverseOrder) {
      parameters['reverseOrder'] = reverseOrder.toString();
    }
    parameters['perPage'] = (perPage ?? _runtime.configuration.perPageCount)
        .toString();
    if (page > 0) {
      parameters['page'] = page.toString();
    }
    if (query.isNotEmpty) {
      parameters['query'] = query;
    }
    return _get('/folders/type/$folderType', parameters, 'getFolderByType');
  }

  /// Ruft Ordner-Inhalte über die Objekt-ID (OID) ab
  ///
  /// Lädt den Inhalt eines spezifischen Ordners anhand seiner eindeutigen
  /// Objekt-ID mit Paginierung und Suchoptionen.
  ///
  /// [oid] - Die eindeutige Objekt-ID des Ordners
  /// [reverseOrder] - Umgekehrte Sortierreihenfolge (Standard: false)
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Elemente pro Seite (Standard: aus Konfiguration)
  /// [query] - Suchtext zum Filtern der Ergebnisse
  ///
  /// Returns: [RestApiResponse] mit Ordner-Inhalten und Dokumenten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.folders.getFolderByOid(
  ///   "folder-oid-12345",
  ///   query: "vertrag",
  ///   perPage: 50
  /// );
  /// ```
  Future<RestApiResponse> getFolderByOid(
    String oid, {
    bool reverseOrder = false,
    int page = 0,
    int? perPage,
    String query = '',
  }) {
    final Map<String, String> parameters = <String, String>{};
    if (reverseOrder) {
      parameters['reverseOrder'] = reverseOrder.toString();
    }
    if (page > 0) {
      parameters['page'] = page.toString();
    }
    parameters['perPage'] = (perPage ?? _runtime.configuration.perPageCount)
        .toString();
    if (query.isNotEmpty) {
      parameters['query'] = query;
    }
    return _get('/folders/oid/$oid', parameters, 'getFolderByOid');
  }

  /// Ruft Ordner-Inhalte über den Ordner-Pfad ab
  ///
  /// Lädt den Inhalt eines Ordners anhand seines hierarchischen Pfads
  /// im Dateisystem mit Paginierung und Suchfunktionen.
  ///
  /// [path] - Der vollständige Pfad zum Ordner (z.B. "/Projekte/2024/Projekt1")
  /// [reverseOrder] - Umgekehrte Sortierreihenfolge (Standard: false)
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Elemente pro Seite (Standard: aus Konfiguration)
  /// [query] - Suchtext zum Filtern der Ergebnisse
  ///
  /// Returns: [RestApiResponse] mit Ordner-Inhalten und Navigationsdaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.folders.getFolderByPath(
  ///   "/Dokumente/Verträge/2024",
  ///   reverseOrder: true,
  ///   query: "kunde"
  /// );
  /// ```
  Future<RestApiResponse> getFolderByPath(
    String path, {
    bool reverseOrder = false,
    int page = 0,
    int? perPage,
    String query = '',
  }) {
    String encodedPath = Uri.encodeComponent(path);
    if (_runtime.configuration.useFolderPathEncoding) {
      encodedPath = encodedPath.replaceAll('%5C', '%255C');
    }
    final Map<String, String> parameters = <String, String>{};
    if (reverseOrder) {
      parameters['reverseOrder'] = reverseOrder.toString();
    }
    if (page > 0) {
      parameters['page'] = page.toString();
    }
    parameters['perPage'] = (perPage ?? _runtime.configuration.perPageCount)
        .toString();
    if (query.isNotEmpty) {
      parameters['query'] = query;
    }
    return _get('/folders/path/$encodedPath', parameters, 'getFolderByPath');
  }

  /// Erstellt einen Unterordner
  ///
  /// Legt einen neuen Ordner als Unterordner eines bestehenden Ordners an.
  /// Unterstützt verschiedene Ordnertypen und hierarchische Strukturen.
  ///
  /// [folderName] - Name des neuen Ordners
  /// [parentFolder] - ID oder Pfad des übergeordneten Ordners
  /// [parentFolderSourceType] - Typ des übergeordneten Ordners (Standard: path)
  ///
  /// Returns: [RestApiResponse] mit der neuen Ordner-ID
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.folders.postFolders(
  ///   "Neuer Unterordner",
  ///   "/Dokumente/Projekte",
  ///   parentFolderSourceType: RestApiFolderType.path
  /// );
  /// ```
  Future<RestApiResponse> postFolders(
    String folderName,
    String parentFolder, {
    RestApiDOCUframeFolderType parentFolderSourceType =
        RestApiDOCUframeFolderType.path,
  }) {
    return _execute(
      method: ApiHttpMethod.post,
      path: '/folders',
      body: jsonEncode(<String, dynamic>{
        'folderName': folderName,
        'parentFolder': parentFolder,
        'parentFolderSourceType': parentFolderSourceType.value,
      }),
      operation: 'postFolders',
    );
  }

  /// Löscht einen Ordner
  ///
  /// Entfernt einen Ordner und optional seinen gesamten Inhalt aus dem System.
  /// Diese Aktion kann nicht rückgängig gemacht werden.
  ///
  /// [path] - Der vollständige Pfad zum zu löschenden Ordner
  /// [notEmpty] - Wenn true, wird der Ordner auch gelöscht, wenn er nicht leer ist (Standard: false)
  ///
  /// Returns: [RestApiResponse] mit dem Löschstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.folders.deleteFolders("/Temp/Alter_Ordner", notEmpty: true);
  /// if (response.isOk) {
  ///   print("Ordner erfolgreich gelöscht");
  /// }
  /// ```
  Future<RestApiResponse> deleteFolders(String path, {bool notEmpty = false}) {
    final Map<String, String> parameters = <String, String>{};
    if (path.isNotEmpty) {
      parameters['path'] = path;
    }
    if (notEmpty) {
      parameters['notEmpty'] = notEmpty.toString();
    }
    return _execute(
      method: ApiHttpMethod.delete,
      path: '/folders',
      queryParameters: parameters,
      operation: 'deleteFolders',
    );
  }

  /// Benennt einen Ordner um
  ///
  /// Ändert den Namen eines bestehenden Ordners ohne Änderung der Struktur
  /// oder des Inhalts.
  ///
  /// [oid] - Die Objekt-ID des umzubenennenden Ordners
  /// [newName] - Der neue Name für den Ordner
  ///
  /// Returns: [RestApiResponse] mit dem Umbenennungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.folders.patchFoldersRename(
  ///   "folder-oid-12345",
  ///   "Neuer Ordnername"
  /// );
  /// ```
  Future<RestApiResponse> patchFoldersRename(String oid, String newName) {
    return _execute(
      method: ApiHttpMethod.patch,
      path: '/folders/rename/$oid',
      body: jsonEncode(<String, dynamic>{'folderName': newName}),
      operation: 'patchFoldersRename',
    );
  }

  /// Fügt Dokumente zu einem Ordner hinzu
  ///
  /// Verknüpft eine Liste von Dokumenten mit einem bestimmten Ordner.
  /// Die Dokumente bleiben an ihrem ursprünglichen Speicherort.
  ///
  /// [folderType] - Der Typ des Zielordners
  /// [folderId] - Die ID des Zielordners
  /// [documentOids] - Liste der Dokument-OIDs zum Hinzufügen
  /// [className] - Klassenname für spezielle Ordnertypen (Favoriten, Historie)
  ///
  /// Returns: [RestApiResponse] mit dem Hinzufügungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.folders.patchFoldersAdd(
  ///   RestApiFolderType.path,
  ///   "/Projekte/Projekt1",
  ///   ["doc-123", "doc-456", "doc-789"]
  /// );
  /// ```
  Future<RestApiResponse> patchFoldersAdd(
    RestApiDOCUframeFolderType folderType,
    String folderId,
    List<String> documentOids, {
    String className = '',
  }) {
    return _execute(
      method: ApiHttpMethod.patch,
      path:
          '/folders/add/${Uri.encodeComponent(folderType.value)}/'
          '${Uri.encodeComponent(folderId)}',
      queryParameters: className.isEmpty
          ? const <String, String>{}
          : <String, String>{'class': className},
      body: jsonEncode(<String, dynamic>{'documents': documentOids}),
      operation: 'patchFoldersAdd',
    );
  }

  /// Entfernt Dokumente aus einem Ordner
  ///
  /// Entfernt die Verknüpfung von Dokumenten zu einem Ordner.
  /// Optional können die Dokumente in den Papierkorb verschoben werden.
  ///
  /// [folderType] - Der Typ des Quellordners
  /// [folderId] - Die ID des Quellordners
  /// [documentOids] - Liste der zu entfernenden Dokument-OIDs
  /// [className] - Klassenname für spezielle Ordnertypen (Favoriten, Historie)
  /// [moveToTrashBin] - Dokumente in Papierkorb verschieben (Standard: true)
  /// [deep] - Tiefe Entfernung aus Unterordnern (Standard: false)
  ///
  /// Returns: [RestApiResponse] mit dem Entfernungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.folders.patchFoldersRemoveDocuments(
  ///   RestApiFolderType.oid,
  ///   "folder-oid-12345",
  ///   ["doc-123", "doc-456"],
  ///   moveToTrashBin: false
  /// );
  /// ```
  Future<RestApiResponse> patchFoldersRemoveDocuments(
    RestApiDOCUframeFolderType folderType,
    String folderId,
    List<String> documentOids, {
    String className = '',
    bool moveToTrashBin = true,
    dynamic deep = false,
  }) {
    return _execute(
      method: ApiHttpMethod.patch,
      path:
          '/folders/remove/${Uri.encodeComponent(folderType.value)}/'
          '${Uri.encodeComponent(folderId)}',
      queryParameters: className.isEmpty
          ? const <String, String>{}
          : <String, String>{'class': className},
      body: jsonEncode(<String, dynamic>{
        'documents': documentOids,
        'moveToTrashBin': moveToTrashBin,
        'deep': deep,
      }),
      operation: 'patchFoldersRemoveDocuments',
    );
  }

  /// Kopiert oder verschiebt Dokumente zwischen Ordnern
  ///
  /// Transferiert Dokumente von einem Quellordner zu einem Zielordner.
  /// Unterstützt sowohl Kopieren als auch Verschieben von Dokumenten.
  ///
  /// [destinationFolderSourceType] - Typ des Zielordners
  /// [destinationFolderId] - ID des Zielordners
  /// [documentOids] - Liste der zu kopierenden/verschiebenden Dokument-OIDs
  /// [sourceFolderSourceType] - Typ des Quellordners (optional)
  /// [sourceFolderId] - ID des Quellordners (optional)
  /// [cut] - true = verschieben, false = kopieren (Standard: true)
  ///
  /// Returns: [RestApiResponse] mit dem Transfer-Status
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.folders.patchFoldersCopyDocuments(
  ///   RestApiFolderType.path,
  ///   "/Archiv/2024",
  ///   ["doc-123", "doc-456"],
  ///   sourceFolderSourceType: RestApiFolderType.path,
  ///   sourceFolderId: "/Temp",
  ///   cut: true // verschieben
  /// );
  /// ```
  Future<RestApiResponse> patchFoldersCopyDocuments(
    RestApiDOCUframeFolderType destinationFolderSourceType,
    String destinationFolderId,
    List<String> documentOids, {
    RestApiDOCUframeFolderType? sourceFolderSourceType,
    String? sourceFolderId,
    bool cut = true,
  }) {
    final Map<String, dynamic> body = <String, dynamic>{
      'destinationFolderSourceType': destinationFolderSourceType.value,
      'destinationFolder': destinationFolderId,
    };
    if (sourceFolderSourceType != null) {
      body['sourceFolderSourceType'] = sourceFolderSourceType.value;
    }
    if (sourceFolderId != null) {
      body['sourceFolder'] = sourceFolderId;
    }
    body['documents'] = documentOids;
    body['cut'] = cut;

    return _execute(
      method: ApiHttpMethod.patch,
      path: '/folders/copyDocuments',
      body: jsonEncode(body),
      operation: 'patchFoldersCopyDocuments',
    );
  }

  Future<RestApiResponse> _get(
    String path,
    Map<String, String> queryParameters,
    String operation,
  ) {
    return _execute(
      method: ApiHttpMethod.get,
      path: path,
      queryParameters: queryParameters,
      operation: operation,
    );
  }

  Future<RestApiResponse> _execute({
    required ApiHttpMethod method,
    required String path,
    Map<String, String>? queryParameters,
    String? body,
    required String operation,
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
        operationId: 'v1.folders.$operation',
      ),
    );
  }
}
