part of '../../../docuframe_api.dart';

/// Native Objektoperationen der V1-Fassade.
class V1ObjectsApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();
  static const LegacyResponsePolicy<RestApiObjectLockResponse>
  _objectLockResponsePolicy = LegacyResponsePolicy<RestApiObjectLockResponse>(
    RestApiObjectLockResponse.new,
  );

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1ObjectsApi.internal(this._runtime);

  /// Ruft Objektdaten anhand der Objekt-ID ab
  ///
  /// Lädt die vollständigen Daten eines bestimmten Objekts aus der Datenbank
  /// mit optionaler Klassenfilterung und Serialisierungsoptionen.
  ///
  /// [objectOid] - Die eindeutige Objekt-ID
  /// [className] - Optionale Klassenfilterung (z.B. "Vorgang", "Adresse")
  /// [serialization] - Serialisierungsoptionen für die Datenausgabe
  ///
  /// Returns: [RestApiResponse] mit den Objektdaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.objects.getObject(
  ///   "obj-12345",
  ///   className: "Vorgang",
  ///   serialization: '{"type":"full"}'
  /// );
  /// if (response.isOk) {
  ///   Map<String, dynamic> objectData = response.data;
  /// }
  /// ```
  Future<RestApiResponse> getObject(
    String objectOid, {
    String className = '',
    String serialization = '',
  }) {
    final Map<String, String> parameters = <String, String>{};
    if (className.isNotEmpty) {
      parameters['class'] = className;
    }
    if (serialization.isNotEmpty) {
      parameters['serialization'] = serialization;
    }
    return _execute(
      method: ApiHttpMethod.get,
      path: '/object/$objectOid',
      queryParameters: parameters,
      operation: 'getObject',
    );
  }

  /// Erstellt ein neues Objekt in der Datenbank
  ///
  /// Legt ein neues Objekt der angegebenen Klasse mit den bereitgestellten
  /// Daten an. Unterstützt verschiedene Speichermodi und Aktionen.
  ///
  /// [className] - Der Name der Objektklasse (z.B. "Vorgang", "Adresse", "Projekt")
  /// [body] - JSON-String mit den Objektdaten
  /// [storeMode] - Speichermodus (0=DBOModifyMember, 10=DBOSet)
  /// [serialization] - Serialisierungsoptionen für die Antwort
  /// [actions] - Zusätzliche Aktionen nach dem Speichern
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit der neuen Objekt-ID
  ///
  /// Beispiel:
  /// ```dart
  /// String objectData = jsonEncode({
  ///   "name": "Neuer Vorgang",
  ///   "description": "Beschreibung des Vorgangs"
  /// });
  /// RestApiResponse response = await api.v1.objects.postObject(
  ///   "Vorgang",
  ///   objectData
  /// );
  /// ```
  Future<RestApiResponse> postObject(
    String className,
    String body, {
    int storeMode = 0,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) {
    final Map<String, String> parameters = <String, String>{};
    if (storeMode != 0) {
      parameters['storeMode'] = storeMode.toString();
    }
    if (actions.isNotEmpty) {
      parameters['actions'] = actions;
    }
    if (serialization.isNotEmpty) {
      parameters['serialization'] = serialization;
    }
    if (rightsControlKey.isNotEmpty) {
      parameters['rightsControlKey'] = rightsControlKey;
    }
    return _execute(
      method: ApiHttpMethod.post,
      path: '/object/$className',
      queryParameters: parameters,
      body: body,
      operation: 'postObject',
    );
  }

  /// Bearbeitet ein bestehendes Objekt
  ///
  /// Aktualisiert die Daten eines vorhandenen Objekts in der Datenbank
  /// mit verschiedenen Speichermodi und Sicherheitsrichtlinien.
  ///
  /// [objectOid] - Die Objekt-ID des zu bearbeitenden Objekts
  /// [body] - JSON-String mit den aktualisierten Objektdaten
  /// [storeMode] - Speichermodus (0=DBOModifyMember, 10=DBOSet)
  /// [storeSecurityPolice] - Sicherheitsrichtlinie (0=EQ, 10=GT_NOLIST, etc.)
  /// [serialization] - Serialisierungsoptionen für die Antwort
  /// [actions] - Zusätzliche Aktionen nach dem Speichern
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// String updatedData = jsonEncode({
  ///   "name": "Aktualisierter Name",
  ///   "status": "In Bearbeitung"
  /// });
  /// RestApiResponse response = await api.v1.objects.patchObject(
  ///   "obj-12345",
  ///   updatedData,
  ///   storeMode: 10
  /// );
  /// ```
  Future<RestApiResponse> patchObject(
    String objectOid,
    String body, {
    int storeMode = 0,
    int storeSecurityPolice = 0,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) {
    final Map<String, String> parameters = <String, String>{};
    if (storeMode != 0) {
      parameters['storeMode'] = storeMode.toString();
    }
    if (storeSecurityPolice != 0) {
      parameters['storeSecurityPolice'] = storeSecurityPolice.toString();
    }
    if (actions.isNotEmpty) {
      parameters['actions'] = actions;
    }
    if (serialization.isNotEmpty) {
      parameters['serialization'] = serialization;
    }
    if (rightsControlKey.isNotEmpty) {
      parameters['rightsControlKey'] = rightsControlKey;
    }
    return _execute(
      method: ApiHttpMethod.patch,
      path: '/object/$objectOid',
      queryParameters: parameters,
      body: body,
      operation: 'patchObject',
    );
  }

  /// Löscht ein Objekt aus der Datenbank
  ///
  /// Entfernt ein Objekt permanent oder verschiebt es in den Papierkorb,
  /// abhängig von den Systemeinstellungen und Aktionen.
  ///
  /// [objectOid] - Die Objekt-ID des zu löschenden Objekts
  /// [actions] - Zusätzliche Aktionen beim Löschen (z.B. Benachrichtigungen)
  /// [moveToRecycler] - Wenn true, wird das Objekt via MoveToRecycler gelöscht (Standard: false)
  ///
  /// Returns: [RestApiResponse] mit dem Löschstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.objects.deleteObject("obj-12345");
  /// if (response.isOk) {
  ///   print("Objekt erfolgreich gelöscht");
  /// }
  /// ```
  Future<RestApiResponse> deleteObject(
    String objectOid, {
    String actions = '',
    bool moveToRecycler = false,
  }) {
    final Map<String, String> parameters = <String, String>{};
    if (actions.isNotEmpty) {
      parameters['actions'] = actions;
    }
    if (moveToRecycler) {
      parameters['moveToRecycler'] = moveToRecycler.toString();
    }
    return _execute(
      method: ApiHttpMethod.delete,
      path: '/object/$objectOid',
      queryParameters: parameters,
      operation: 'deleteObject',
    );
  }

  /// Ruft eine Liste von Objekten einer bestimmten Klasse ab
  ///
  /// Lädt alle Objekte einer spezifizierten Klasse mit Filterung,
  /// Paginierung und Suchfunktionalität.
  ///
  /// [className] - Name der Objektklasse (z.B. "Vorgang", "Adresse", "Projekt")
  /// [query] - Suchfilter für die Objektliste
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Objekte pro Seite (Standard: aus Konfiguration)
  /// [serialization] - Serialisierungsoptionen für die Ausgabe
  /// [actions] - Zusätzliche Aktionen
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit der Objektliste und Metadaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.objects.getObjects(
  ///   "Vorgang",
  ///   query: "status:offen",
  ///   page: 1,
  ///   perPage: 25
  /// );
  /// if (response.isOk) {
  ///   List objects = response.data['data'];
  /// }
  /// ```
  Future<RestApiResponse> getObjects(
    String className, {
    String query = '',
    int page = 0,
    int? perPage,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) {
    return _execute(
      method: ApiHttpMethod.get,
      path: '/objects/$className',
      queryParameters: _listParameters(
        query: query,
        page: page,
        perPage: perPage,
        serialization: serialization,
        actions: actions,
        rightsControlKey: rightsControlKey,
      ),
      operation: 'getObjects',
    );
  }

  /// Bearbeitet mehrere Objekte einer Klasse gleichzeitig
  ///
  /// Aktualisiert alle Objekte einer bestimmten Klasse, die den Suchkriterien
  /// entsprechen, mit den gleichen Daten. Massenbearbeitung von Objekten.
  ///
  /// [className] - Name der Objektklasse für die Massenbearbeitung
  /// [query] - Suchfilter zur Auswahl der zu bearbeitenden Objekte
  /// [body] - JSON-String mit den Aktualisierungsdaten
  /// [storeMode] - Speichermodus (0=DBOModifyMember, 10=DBOSet)
  /// [storeSecurityPolice] - Sicherheitsrichtlinie für die Bearbeitung
  /// [serialization] - Serialisierungsoptionen für die Antwort
  /// [actions] - Zusätzliche Aktionen nach dem Speichern
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit dem Status der Massenbearbeitung
  ///
  /// Beispiel:
  /// ```dart
  /// String updateData = jsonEncode({"status": "archiviert"});
  /// RestApiResponse response = await api.v1.objects.patchObjects(
  ///   "Vorgang",
  ///   query: "created:<2023-01-01",
  ///   body: updateData
  /// );
  /// ```
  Future<RestApiResponse> patchObjects(
    String className, {
    String query = '',
    String body = '',
    int storeMode = 0,
    int storeSecurityPolice = 0,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) {
    final Map<String, String> parameters = <String, String>{};
    if (query.isNotEmpty) {
      parameters['query'] = query;
    }
    if (actions.isNotEmpty) {
      parameters['actions'] = actions;
    }
    if (serialization.isNotEmpty) {
      parameters['serialization'] = serialization;
    }
    if (rightsControlKey.isNotEmpty) {
      parameters['rightsControlKey'] = rightsControlKey;
    }
    if (storeSecurityPolice != 0) {
      parameters['storeSecurityPolice'] = storeSecurityPolice.toString();
    }
    if (storeMode != 0) {
      parameters['storeMode'] = storeMode.toString();
    }
    return _execute(
      method: ApiHttpMethod.patch,
      path: '/objects/$className',
      queryParameters: parameters,
      body: body,
      operation: 'patchObjects',
    );
  }

  /// Führt eine Aktion auf Objekten einer bestimmten Klasse aus
  ///
  /// Sendet einen POST-Request an den `v1/action`-Endpunkt, um eine serverseitige
  /// Aktion für Objekte einer spezifizierten Klasse auszulösen. Unterstützt
  /// Filterung, Paginierung und Serialisierungsoptionen.
  ///
  /// [className] - Name der Objektklasse, auf der die Aktion ausgeführt wird
  ///   (z.B. "Vorgang", "Adresse", "Projekt")
  /// [query] - Suchfilter zur Auswahl der betroffenen Objekte
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Objekte pro Seite (Standard: aus Konfiguration)
  /// [serialization] - Serialisierungsoptionen für die Antwort
  /// [actions] - JSON-kodierte Liste der auszuführenden Aktionen. Jede Aktion
  ///   ist ein Objekt mit mindestens `type` sowie aktionsspezifischen Feldern
  ///   (z.B. `text`, `toUsers`, `cc`, `public` für den Typ `sendObject`)
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit dem Ergebnis der ausgeführten Aktion
  ///
  /// Beispiel:
  /// ```dart
  /// final actions = jsonEncode([
  ///   {
  ///     "type": "sendObject",
  ///     "text": "test",
  ///     "toUsers": ["Demo"],
  ///     "cc": [],
  ///     "public": false,
  ///   }
  /// ]);
  /// RestApiResponse response = await api.v1.objects.postAction(
  ///   "GSDObjekt",
  ///   query: jsonEncode({"oids": ["V2YZ"]}),
  ///   actions: actions,
  /// );
  /// if (response.isOk) {
  ///   print("Aktion erfolgreich ausgeführt");
  /// }
  /// ```
  Future<RestApiResponse> postAction(
    String className, {
    String query = '',
    int page = 0,
    int? perPage,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) {
    return _execute(
      method: ApiHttpMethod.post,
      path: '/action/$className',
      queryParameters: _listParameters(
        query: query,
        page: page,
        perPage: perPage,
        serialization: serialization,
        actions: actions,
        rightsControlKey: rightsControlKey,
      ),
      operation: 'postAction',
    );
  }

  /// Ruft den Sperrstatus eines Objekts ab.
  ///
  /// Lädt über `GET v1/lock/object/{id}`, ob und durch wen das angegebene
  /// Objekt aktuell gesperrt ist.
  ///
  /// [id] - OID oder UUID des zu prüfenden Objekts
  ///
  /// Returns: [RestApiObjectLockResponse] mit Sperrstatus und Meldungen
  Future<RestApiObjectLockResponse> getLockObject(String id) {
    return _runtime.execute(
      ApiRequest<RestApiObjectLockResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v1,
        path: '/lock/object/$id',
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _objectLockResponsePolicy,
        operationId: 'v1.objects.getLockObject',
      ),
    );
  }

  /// Ruft die Hierarchie von Aktionen/Vorgängen ab
  ///
  /// Lädt die vollständige Baum-Struktur von Unter-Aktionen eines Vorgangs
  /// mit konfigurierbarer Tiefe und Serialisierungsoptionen.
  ///
  /// [oid] - Die Objekt-ID des Haupt-Vorgangs
  /// [deepLevel] - Maximale Verschachtelungstiefe (-1 = unbegrenzt)
  /// [serialization] - Serialisierungsoptionen für die Ausgabe
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit der hierarchischen Aktions-Struktur
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.objects.getIncidentTree(
  ///   "incident-12345",
  ///   deepLevel: 3,
  ///   serialization: '{"includeChildren": true}'
  /// );
  /// ```
  Future<RestApiResponse> getIncidentTree(
    String oid, {
    int deepLevel = -1,
    String serialization = '',
    String rightsControlKey = '',
  }) {
    final Map<String, String> parameters = <String, String>{};
    if (deepLevel != -1) {
      parameters['deepLevel'] = deepLevel.toString();
    }
    if (serialization.isNotEmpty) {
      parameters['serialization'] = serialization;
    }
    if (rightsControlKey.isNotEmpty) {
      parameters['rightsControlKey'] = rightsControlKey;
    }
    return _execute(
      method: ApiHttpMethod.get,
      path: '/incidentTree/$oid',
      queryParameters: parameters,
      operation: 'getIncidentTree',
    );
  }

  /// Setzt die Objekt-Sicherheitseinstellungen für ein Dokument/Objekt
  ///
  /// Definiert oder aktualisiert die Zugriffsrechte für bestimmte Benutzer
  /// auf ein spezifisches Objekt im System. Jeder Benutzer erhält
  /// individuelle Rechte-Flags, die die erlaubten Aktionen bestimmen.
  ///
  /// [oid] - Die eindeutige Objekt-ID des zu konfigurierenden Elements
  /// [userObjectSecurity] - Map mit Benutzername als Key und Rechte-Flags als Value
  /// [replace] - Ob bestehende Rechte ersetzt werden sollen (Standard: false)
  ///
  /// Returns: [RestApiResponse] mit dem Status der Sicherheitskonfiguration
  ///
  /// **Map-Format:**
  /// ```json
  /// {
  ///   "userObjectName": "test1",
  ///   "rights": 7
  /// }
  /// ```
  ///
  /// Beispiel:
  /// ```dart
  /// Map<String, int> security = {
  ///   "user1": 7,
  ///   "user2": 15,
  /// };
  /// RestApiResponse response = await api.v1.objects.setObjectSecurity(
  ///   "A12BC",
  ///   security,
  ///   replace: true
  /// );
  /// ```
  Future<RestApiResponse> setObjectSecurity(
    String oid,
    Map<String, int> userObjectSecurity, {
    bool replace = false,
  }) {
    final List<Map<String, dynamic>> security = <Map<String, dynamic>>[];
    userObjectSecurity.forEach((String userObjectName, int rights) {
      security.add(<String, dynamic>{
        'userObjectName': userObjectName,
        'rights': rights,
      });
    });
    final Map<String, dynamic> body = <String, dynamic>{'security': security};
    if (replace) {
      body['replace'] = replace;
    }
    return _execute(
      method: ApiHttpMethod.post,
      path: '/setObjectSecurity/$oid',
      body: jsonEncode(body),
      operation: 'setObjectSecurity',
    );
  }

  Map<String, String> _listParameters({
    required String query,
    required int page,
    required int? perPage,
    required String serialization,
    required String actions,
    required String rightsControlKey,
  }) {
    final Map<String, String> parameters = <String, String>{};
    if (query.isNotEmpty) {
      parameters['query'] = query;
    }
    if (page != 0) {
      parameters['page'] = page.toString();
    }
    parameters['perPage'] = (perPage ?? _runtime.configuration.perPageCount)
        .toString();
    if (serialization.isNotEmpty) {
      parameters['serialization'] = serialization;
    }
    if (actions.isNotEmpty) {
      parameters['actions'] = actions;
    }
    if (rightsControlKey.isNotEmpty) {
      parameters['rightsControlKey'] = rightsControlKey;
    }
    return parameters;
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
        operationId: 'v1.objects.$operation',
      ),
    );
  }
}
