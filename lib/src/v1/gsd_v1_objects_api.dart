import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/gsd_object_lock.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/deduplication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/model_response_policy.dart';
import 'package:gsd_restapi/src/v1/v1_requester.dart';
import 'package:meta/meta.dart';

/// Native Objektoperationen der V1-Fassade.
class GsdV1ObjectsApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1ObjectsApi.internal(this._runtime);
  late final V1Requester _requests = V1Requester(_runtime, 'objects');
  static const ModelResponsePolicy<GsdObjectLock> _objectLockResponsePolicy =
      ModelResponsePolicy<GsdObjectLock>(GsdObjectLock.fromJson);

  final ApiRuntime _runtime;

  /// Ruft Objektdaten anhand der Objekt-ID ab
  ///
  /// Lädt die vollständigen Daten eines bestimmten Objekts aus der Datenbank
  /// mit optionaler Klassenfilterung und Serialisierungsoptionen.
  ///
  /// [objectOid] - Die eindeutige Objekt-ID
  /// [className] - Optionale Klassenfilterung (z.B. "Vorgang", "Adresse")
  /// [serialization] - Serialisierungsoptionen für die Datenausgabe
  ///
  /// Returns: `data` der Antwort mit den Objektdaten
  ///
  /// Beispiel:
  /// ```dart
  /// final objectData = await api.v1.objects.getObject(
  ///   "obj-12345",
  ///   className: "Vorgang",
  ///   serialization: '{"type":"full"}'
  /// ) as Map<String, Object?>;
  /// ```
  Future<Object?> getObject(
    String objectOid, {
    String className = '',
    String serialization = '',
  }) {
    final parameters = <String, String>{};
    if (className.isNotEmpty) {
      parameters['class'] = className;
    }
    if (serialization.isNotEmpty) {
      parameters['serialization'] = serialization;
    }
    return _requests.execute(
      method: GsdHttpMethod.get,
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
  /// [className] - Der Name der Objektklasse (z.B. "Vorgang", "Adresse",
  ///   "Projekt")
  /// [body] - JSON-String mit den Objektdaten
  /// [storeMode] - Speichermodus (0=DBOModifyMember, 10=DBOSet)
  /// [serialization] - Serialisierungsoptionen für die Antwort
  /// [actions] - Zusätzliche Aktionen nach dem Speichern
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: `data` der Antwort mit der neuen Objekt-ID
  ///
  /// Beispiel:
  /// ```dart
  /// String objectData = jsonEncode({
  ///   "name": "Neuer Vorgang",
  ///   "description": "Beschreibung des Vorgangs"
  /// });
  /// final data = await api.v1.objects.postObject(
  ///   "Vorgang",
  ///   objectData
  /// );
  /// ```
  Future<Object?> postObject(
    String className,
    String body, {
    int storeMode = 0,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) {
    final parameters = <String, String>{};
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
    return _requests.execute(
      method: GsdHttpMethod.post,
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
  /// Returns: `data` der Antwort mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// String updatedData = jsonEncode({
  ///   "name": "Aktualisierter Name",
  ///   "status": "In Bearbeitung"
  /// });
  /// final data = await api.v1.objects.patchObject(
  ///   "obj-12345",
  ///   updatedData,
  ///   storeMode: 10
  /// );
  /// ```
  Future<Object?> patchObject(
    String objectOid,
    String body, {
    int storeMode = 0,
    int storeSecurityPolice = 0,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) {
    final parameters = <String, String>{};
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
    return _requests.execute(
      method: GsdHttpMethod.patch,
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
  /// [moveToRecycler] - Wenn true, wird das Objekt via MoveToRecycler gelöscht
  ///   (Standard: false)
  ///
  /// Returns: `data` der Antwort mit dem Löschstatus
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.objects.deleteObject("obj-12345");
  /// print("Objekt erfolgreich gelöscht");
  /// ```
  Future<Object?> deleteObject(
    String objectOid, {
    String actions = '',
    bool moveToRecycler = false,
  }) {
    final parameters = <String, String>{};
    if (actions.isNotEmpty) {
      parameters['actions'] = actions;
    }
    if (moveToRecycler) {
      parameters['moveToRecycler'] = moveToRecycler.toString();
    }
    return _requests.execute(
      method: GsdHttpMethod.delete,
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
  /// Returns: `data` der Antwort mit der Objektliste und Metadaten
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.objects.getObjects(
  ///   "Vorgang",
  ///   query: "status:offen",
  ///   page: 1,
  ///   perPage: 25
  /// ) as Map<String, Object?>;
  /// List objects = data['data'] as List;
  /// ```
  Future<Object?> getObjects(
    String className, {
    String query = '',
    int page = 0,
    int? perPage,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) {
    return _requests.execute(
      method: GsdHttpMethod.get,
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
  /// Returns: `data` der Antwort mit dem Status der Massenbearbeitung
  ///
  /// Beispiel:
  /// ```dart
  /// String updateData = jsonEncode({"status": "archiviert"});
  /// final data = await api.v1.objects.patchObjects(
  ///   "Vorgang",
  ///   query: "created:<2023-01-01",
  ///   body: updateData
  /// );
  /// ```
  Future<Object?> patchObjects(
    String className, {
    String query = '',
    String body = '',
    int storeMode = 0,
    int storeSecurityPolice = 0,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) {
    final parameters = <String, String>{};
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
    return _requests.execute(
      method: GsdHttpMethod.patch,
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
  /// Returns: `data` der Antwort mit dem Ergebnis der ausgeführten Aktion
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
  /// final data = await api.v1.objects.postAction(
  ///   "MeinObjekt",
  ///   query: jsonEncode({"oids": ["V2YZ"]}),
  ///   actions: actions,
  /// );
  /// print("Aktion erfolgreich ausgeführt");
  /// ```
  Future<Object?> postAction(
    String className, {
    String query = '',
    int page = 0,
    int? perPage,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) {
    return _requests.execute(
      method: GsdHttpMethod.post,
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
  /// Returns: [GsdObjectLock] mit Sperrstatus und Meldungen
  Future<GsdObjectLock> getLockObject(String id) {
    return _runtime.execute(
      ApiRequest<GsdObjectLock>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v1,
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
  /// Returns: `data` der Antwort mit der hierarchischen Aktions-Struktur
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.objects.getIncidentTree(
  ///   "incident-12345",
  ///   deepLevel: 3,
  ///   serialization: '{"includeChildren": true}'
  /// );
  /// ```
  Future<Object?> getIncidentTree(
    String oid, {
    int deepLevel = -1,
    String serialization = '',
    String rightsControlKey = '',
  }) {
    final parameters = <String, String>{};
    if (deepLevel != -1) {
      parameters['deepLevel'] = deepLevel.toString();
    }
    if (serialization.isNotEmpty) {
      parameters['serialization'] = serialization;
    }
    if (rightsControlKey.isNotEmpty) {
      parameters['rightsControlKey'] = rightsControlKey;
    }
    return _requests.execute(
      method: GsdHttpMethod.get,
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
  /// [userObjectSecurity] - Map mit Benutzername als Key und Rechte-Flags als
  ///   Value
  /// [replace] - Ob bestehende Rechte ersetzt werden sollen (Standard: false)
  ///
  /// Returns: `data` der Antwort mit dem Status der Sicherheitskonfiguration
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
  /// final data = await api.v1.objects.setObjectSecurity(
  ///   "A12BC",
  ///   security,
  ///   replace: true
  /// );
  /// ```
  Future<Object?> setObjectSecurity(
    String oid,
    Map<String, int> userObjectSecurity, {
    bool replace = false,
  }) {
    final security = <Map<String, dynamic>>[];
    userObjectSecurity.forEach((userObjectName, rights) {
      security.add(<String, dynamic>{
        'userObjectName': userObjectName,
        'rights': rights,
      });
    });
    final body = <String, dynamic>{'security': security};
    if (replace) {
      body['replace'] = replace;
    }
    return _requests.execute(
      method: GsdHttpMethod.post,
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
    final parameters = <String, String>{};
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
}
