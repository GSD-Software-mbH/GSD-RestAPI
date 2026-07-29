part of '../../../docuframe_api.dart';

/// Native Operationen für interne Nachrichten der V1-Fassade.
class V1MessagesApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1MessagesApi.internal(this._runtime);

  /// Erstellt eine Nachricht als Entwurf
  ///
  /// Legt eine neue interne Nachricht an mehrere Benutzer als Entwurf an.
  /// Die Nachricht kann später bearbeitet oder direkt gesendet werden.
  ///
  /// [toUsers] - Liste der Empfänger-Benutzernamen
  /// [text] - Nachrichtentext
  /// [name] - Titel/Name der Nachricht
  /// [description] - Zusätzliche Beschreibung
  /// [addToIncomingFolder] - In Eingangsordner hinzufügen (Standard: true)
  /// [originalOid] - OID der ursprünglichen Nachricht (bei Antworten)
  /// [uuid] - Eindeutige UUID für die Nachricht
  /// [serialization] - Serialisierungsoptionen
  /// [rightsControlKey] - Berechtigungsschlüssel
  /// [actions] - Zusätzliche Aktionen
  ///
  /// Returns: [RestApiResponse] mit der Nachrichten-ID
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.messages.postMessage(
  ///   ["mueller", "schmidt"],
  ///   "Wichtige Information zum Projekt...",
  ///   name: "Projekt-Update"
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Erstellt eine Nachricht als Entwurf (`POST v1/message`).
  Future<RestApiResponse> postMessage(
    List<String> toUsers,
    String text, {
    String name = '',
    String description = '',
    bool addToIncomingFolder = true,
    String originalOid = '',
    String uuid = '',
    String serialization = '',
    String rightsControlKey = '',
    String actions = '',
  }) {
    return _execute(
      method: ApiHttpMethod.post,
      path: '/message',
      queryParameters: _query(
        serialization: serialization,
        actions: actions,
        rightsControlKey: rightsControlKey,
      ),
      body: _body(
        toUsers,
        text,
        uuid: uuid,
        name: name,
        description: description,
        addToIncomingFolder: addToIncomingFolder,
        originalOid: originalOid,
      ),
      operation: 'postMessage',
    );
  }

  /// Erstellt und sendet eine Nachricht direkt
  ///
  /// Legt eine neue interne Nachricht an und sendet sie sofort an die
  /// angegebenen Empfänger ohne Zwischenspeicherung als Entwurf.
  ///
  /// [toUsers] - Liste der Empfänger-Benutzernamen
  /// [text] - Nachrichtentext
  /// [name] - Titel/Name der Nachricht
  /// [description] - Zusätzliche Beschreibung
  /// [addToIncomingFolder] - In Eingangsordner hinzufügen (Standard: true)
  /// [originalOid] - OID der ursprünglichen Nachricht (bei Antworten)
  /// [uuid] - Eindeutige UUID für die Nachricht
  /// [serialization] - Serialisierungsoptionen
  /// [rightsControlKey] - Berechtigungsschlüssel
  /// [actions] - Zusätzliche Aktionen
  ///
  /// Returns: [RestApiResponse] mit dem Sendestatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.messages.postMessageSend(
  ///   ["team@firma.de"],
  ///   "Das Meeting findet um 14:00 statt.",
  ///   name: "Meeting-Erinnerung"
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Erstellt und sendet eine Nachricht sofort (`POST v1/message/send`).
  Future<RestApiResponse> postMessageSend(
    List<String> toUsers,
    String text, {
    String name = '',
    String description = '',
    bool addToIncomingFolder = true,
    String originalOid = '',
    String uuid = '',
    String serialization = '',
    String rightsControlKey = '',
    String actions = '',
  }) {
    return _execute(
      method: ApiHttpMethod.post,
      path: '/message/send',
      queryParameters: _query(
        serialization: serialization,
        actions: actions,
        rightsControlKey: rightsControlKey,
      ),
      body: _body(
        toUsers,
        text,
        uuid: uuid,
        name: name,
        description: description,
        addToIncomingFolder: addToIncomingFolder,
        originalOid: originalOid,
      ),
      operation: 'postMessageSend',
    );
  }

  /// Bearbeitet eine Entwurfs-Nachricht
  ///
  /// Aktualisiert eine bestehende Nachricht, die als Entwurf gespeichert ist.
  /// Die Nachricht kann später gesendet oder weiter bearbeitet werden.
  ///
  /// [oid] - Die Objekt-ID der zu bearbeitenden Nachricht
  /// [toUsers] - Liste der Empfänger-Benutzernamen
  /// [text] - Aktualisierter Nachrichtentext
  /// [name] - Neuer Titel/Name der Nachricht
  /// [description] - Aktualisierte Beschreibung
  /// [addToIncomingFolder] - In Eingangsordner hinzufügen (Standard: true)
  /// [originalOid] - OID der ursprünglichen Nachricht (bei Antworten)
  /// [uuid] - Eindeutige UUID für die Nachricht
  /// [serialization] - Serialisierungsoptionen
  /// [rightsControlKey] - Berechtigungsschlüssel
  ///
  /// Returns: [RestApiResponse] mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.messages.patchMessage(
  ///   "msg-12345",
  ///   ["team@firma.de"],
  ///   "Aktualisierte Nachricht...",
  ///   name: "Korrigierte Mitteilung"
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Bearbeitet eine Entwurfs-Nachricht (`PATCH v1/message/{oid}`).
  ///
  /// Anders als post* akzeptiert diese Route keinen `actions`-Query.
  Future<RestApiResponse> patchMessage(
    String oid,
    List<String> toUsers,
    String text, {
    String name = '',
    String description = '',
    bool addToIncomingFolder = true,
    String originalOid = '',
    String uuid = '',
    String serialization = '',
    String rightsControlKey = '',
  }) {
    return _execute(
      method: ApiHttpMethod.patch,
      path: '/message/$oid',
      queryParameters: _query(
        serialization: serialization,
        rightsControlKey: rightsControlKey,
      ),
      body: _body(
        toUsers,
        text,
        uuid: uuid,
        name: name,
        description: description,
        addToIncomingFolder: addToIncomingFolder,
        originalOid: originalOid,
      ),
      operation: 'patchMessage',
    );
  }

  /// Bearbeitet und sendet eine Nachricht direkt
  ///
  /// Aktualisiert eine bestehende Nachricht und sendet sie sofort an die
  /// angegebenen Empfänger. Kombiniert Bearbeitung und Versand in einem Schritt.
  ///
  /// [oid] - Die Objekt-ID der zu bearbeitenden und sendenden Nachricht
  /// [toUsers] - Liste der Empfänger-Benutzernamen
  /// [text] - Aktualisierter Nachrichtentext
  /// [name] - Neuer Titel/Name der Nachricht
  /// [description] - Aktualisierte Beschreibung
  /// [addToIncomingFolder] - In Eingangsordner hinzufügen (Standard: true)
  /// [originalOid] - OID der ursprünglichen Nachricht (bei Antworten)
  /// [uuid] - Eindeutige UUID für die Nachricht
  /// [serialization] - Serialisierungsoptionen
  /// [rightsControlKey] - Berechtigungsschlüssel
  ///
  /// Returns: [RestApiResponse] mit dem Sendestatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.messages.patchMessageSend(
  ///   "msg-12345",
  ///   ["empfaenger@firma.de"],
  ///   "Finale Version der Nachricht",
  ///   name: "Wichtige Mitteilung - Final"
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Bearbeitet und sendet eine Nachricht sofort
  /// (`PATCH v1/message/send/{oid}`).
  ///
  /// Anders als post* akzeptiert diese Route keinen `actions`-Query.
  Future<RestApiResponse> patchMessageSend(
    String oid,
    List<String> toUsers,
    String text, {
    String name = '',
    String description = '',
    bool addToIncomingFolder = true,
    String originalOid = '',
    String uuid = '',
    String serialization = '',
    String rightsControlKey = '',
  }) {
    return _execute(
      method: ApiHttpMethod.patch,
      path: '/message/send/$oid',
      queryParameters: _query(
        serialization: serialization,
        rightsControlKey: rightsControlKey,
      ),
      body: _body(
        toUsers,
        text,
        uuid: uuid,
        name: name,
        description: description,
        addToIncomingFolder: addToIncomingFolder,
        originalOid: originalOid,
      ),
      operation: 'patchMessageSend',
    );
  }

  /// Baut den für alle vier Message-Methoden identischen Body.
  ///
  /// Der Legacy-Manager weist `name` am Ende ein zweites Mal zu (toter Code,
  /// gleicher Schlüssel/Wert) - dies wird nicht reproduziert, da die
  /// JSON-Ausgabe (Schlüssel-Reihenfolge über die Erstzuweisung bestimmt)
  /// unverändert bleibt.
  String _body(
    List<String> toUsers,
    String text, {
    required String uuid,
    required String name,
    required String description,
    required bool addToIncomingFolder,
    required String originalOid,
  }) {
    final Map<String, dynamic> body = <String, dynamic>{
      'toUsers': toUsers,
      'text': text,
    };
    if (uuid.isNotEmpty) body['~UUID'] = uuid;
    if (name.isNotEmpty) body['name'] = name;
    if (description.isNotEmpty) body['description'] = description;
    if (addToIncomingFolder) body['addToIncomingFolder'] = addToIncomingFolder;
    if (originalOid.isNotEmpty) body['originalOid'] = originalOid;
    return jsonEncode(body);
  }

  /// Query im Legacy-Insert-Order: serialization, [actions], rightsControlKey.
  /// `actions` wird für patch* nicht übergeben (dort nicht unterstützt).
  Map<String, String> _query({
    required String serialization,
    String? actions,
    required String rightsControlKey,
  }) {
    final Map<String, String> query = <String, String>{};
    if (serialization.isNotEmpty) query['serialization'] = serialization;
    if (actions != null && actions.isNotEmpty) query['actions'] = actions;
    if (rightsControlKey.isNotEmpty) {
      query['rightsControlKey'] = rightsControlKey;
    }
    return query;
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
        queryParameters: (queryParameters == null || queryParameters.isEmpty)
            ? null
            : queryParameters,
        body: body,
        authentication: AuthenticationPolicy.session,
        deduplication: method == ApiHttpMethod.get
            ? DeduplicationPolicy.enabled
            : DeduplicationPolicy.disabled,
        responsePolicy: _responsePolicy,
        operationId: 'v1.messages.$operation',
      ),
    );
  }
}
