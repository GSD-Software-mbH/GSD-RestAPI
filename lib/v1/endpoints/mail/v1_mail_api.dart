part of '../../../docuframe_api.dart';

/// Native E-Mail-Operationen der V1-Fassade.
///
/// Fehler des Servers werden bewusst NICHT abgefangen oder übersetzt - die
/// drei serverseitig (noch) nicht implementierten Reply-/Forward-APIs bleiben
/// erhalten, weil ihr Client-Vertrag konkret ist.
class V1MailApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1MailApi.internal(this._runtime);

  /// Erstellt eine neue E-Mail als Entwurf
  ///
  /// Legt eine neue E-Mail mit allen erforderlichen Headern und Inhalten an.
  /// Die E-Mail wird als Entwurf gespeichert und kann später bearbeitet oder gesendet werden.
  ///
  /// [uuid] - Eindeutige UUID für die E-Mail (optional)
  /// [from] - Absender-Adresse (Standard: "-")
  /// [to] - Liste der Empfänger-Adressen
  /// [cc] - Liste der CC-Empfänger
  /// [bcc] - Liste der BCC-Empfänger
  /// [subject] - Betreff der E-Mail
  /// [htmlContent] - HTML-Inhalt der E-Mail
  /// [plainContent] - Plain-Text-Inhalt der E-Mail
  /// [template] - Vorlagen-Name für automatische Inhaltserstellung
  /// [templateData] - Daten für die Vorlagen-Verarbeitung
  /// [attachments] - Liste der Anhänge (Format: [{"name": "file.pdf", "data": "base64..."}])
  /// [priorityValue] - Prioritätswert (1=hoch, 3=normal, 5=niedrig)
  /// [acknowledgementRequired] - Lesebestätigung erforderlich
  ///
  /// Returns: [RestApiResponse] mit E-Mail-ID und Erstellungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.mail.postMail(
  ///   to: ["kunde@example.com"],
  ///   subject: "Angebot Nr. 12345",
  ///   htmlContent: "<p>Sehr geehrte Damen und Herren...</p>",
  ///   priorityValue: 2
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Erstellt eine E-Mail als Objekt (`POST v1/mail`).
  Future<RestApiResponse> postMail({
    String uuid = '',
    String from = '-',
    List<String>? to,
    List<String>? cc,
    List<String>? bcc,
    String name = '-',
    String description = '-',
    String subject = '-',
    String htmlContent = '-',
    String plainContent = '-',
    String template = '',
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = 'normal',
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    DateTime? startTime,
    String action = '',
    String actions = '',
    String serialization = '',
    bool assignAddress = false,
    bool assignProject = false,
    bool assignProduct = false,
    bool assignContact = false,
    bool sendAssignReceiver = false,
    bool assignAction = false,
  }) {
    final Map<String, String> query = <String, String>{};
    if (action.isNotEmpty) query['action'] = action;
    if (actions.isNotEmpty) query['actions'] = actions;
    if (serialization.isNotEmpty) query['serialization'] = serialization;

    final Map<String, dynamic> body = <String, dynamic>{
      '~UUID': uuid,
      'from': from,
    };
    if (to != null) body['to'] = to;
    if (cc != null) body['cc'] = cc;
    if (bcc != null) body['bcc'] = bcc;
    body['name'] = name;
    body['description'] = description;
    body['subject'] = subject;
    body['htmlContent'] = htmlContent;
    body['plainContent'] = plainContent;
    if (template != '') body['template'] = template;
    if (templateData != null) body['templateData'] = templateData;
    if (attachments != null) body['attachments'] = attachments;
    body['acknowledgementRequired'] = acknowledgementRequired;
    body['keepCalendar'] = keepCalendar;
    if (startTime != null) body['startTime'] = startTime.toISOFormatString();
    // Bewusste Legacy-Parität: postMail baut priorityValue/priorityText zwar,
    // hängt sie aber NIE an den Body (toter Code im Legacy-Manager). Deshalb
    // gibt es hier - anders als bei patchMail/postMailSend - keinen
    // 'priority'-Schlüssel. priorityValue/priorityText bleiben nur zur
    // Signatur-Kompatibilität erhalten.
    body['assignAddresses'] = assignAddress;
    body['assignProjects'] = assignProject;
    body['assignProducts'] = assignProduct;
    body['assignContacts'] = assignContact;
    body['assignActions'] = assignAction;
    body['sendAssignReceiver'] = sendAssignReceiver;

    return _execute(
      method: ApiHttpMethod.post,
      path: '/mail',
      queryParameters: query,
      body: jsonEncode(body),
      operation: 'postMail',
    );
  }

  /// This request allows to update existing an email, either the uuid or oid are needed
  ///
  /// Hinweis zur neuen API:
  /// Aktualisiert eine bestehende E-Mail (`PATCH v1/mail`); benötigt uuid oder
  /// oid.
  Future<RestApiResponse> patchMail({
    String uuid = '',
    String oid = '',
    String from = '-',
    List<String>? to,
    List<String>? cc,
    List<String>? bcc,
    String name = '-',
    String description = '-',
    String subject = '-',
    String htmlContent = '-',
    String plainContent = '-',
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = 'normal',
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    bool convertImageDataSrcToFileSrc = false,
    DateTime? startTime,
    String actions = '',
  }) {
    final Map<String, String> query = <String, String>{};
    if (actions.isNotEmpty) query['actions'] = actions;

    final Map<String, dynamic> body = <String, dynamic>{};
    if (uuid.isNotEmpty) body['~UUID'] = uuid;
    if (oid.isNotEmpty) body['~ObjectID'] = oid;
    body['from'] = from;
    if (to != null) body['to'] = to;
    if (cc != null) body['cc'] = cc;
    if (bcc != null) body['bcc'] = bcc;
    body['name'] = name;
    body['description'] = description;
    body['subject'] = subject;
    body['htmlContent'] = htmlContent;
    body['plainContent'] = plainContent;
    if (templateData != null) body['templateData'] = templateData;
    if (attachments != null) body['attachments'] = attachments;
    body['acknowledgementRequired'] = acknowledgementRequired;
    body['convertImageDataSrcToFileSrc'] = convertImageDataSrcToFileSrc;
    body['keepCalendar'] = keepCalendar;
    if (startTime != null) body['startTime'] = startTime.toISOFormatString();
    body['priority'] = _priority(priorityValue, priorityText);

    return _execute(
      method: ApiHttpMethod.patch,
      path: '/mail',
      queryParameters: query,
      body: jsonEncode(body),
      operation: 'patchMail',
    );
  }

  /// This request allows to update existing email and send it (when body does not contain any OID a new mail is beeing created)
  ///
  /// Hinweis zur neuen API:
  /// Aktualisiert eine E-Mail und versendet sie (`POST v1/mail/send`); ohne OID
  /// im Body wird eine neue Mail erstellt.
  Future<RestApiResponse> postMailSend({
    String uuid = '',
    String oid = '',
    String from = '-',
    List<String>? to,
    List<String>? cc,
    List<String>? bcc,
    String name = '-',
    String description = '-',
    String subject = '-',
    String htmlContent = '-',
    String plainContent = '-',
    String template = '',
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = 'normal',
    bool convertImageDataSrcToFileSrc = false,
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    bool sendAssignReceiver = false,
    DateTime? startTime,
    String action = '',
    String actions = '',
  }) {
    final Map<String, String> query = <String, String>{};
    if (action.isNotEmpty) query['action'] = action;
    if (actions.isNotEmpty) query['actions'] = actions;

    final Map<String, dynamic> body = <String, dynamic>{
      '~UUID': uuid,
      '~ObjectID': oid,
      'from': from,
    };
    if (to != null) body['to'] = to;
    if (cc != null) body['cc'] = cc;
    if (bcc != null) body['bcc'] = bcc;
    body['name'] = name;
    body['description'] = description;
    body['subject'] = subject;
    body['htmlContent'] = htmlContent;
    body['plainContent'] = plainContent;
    if (template != '') body['template'] = template;
    if (templateData != null) body['templateData'] = templateData;
    if (attachments != null) body['attachments'] = attachments;
    body['acknowledgementRequired'] = acknowledgementRequired;
    body['convertImageDataSrcToFileSrc'] = convertImageDataSrcToFileSrc;
    body['keepCalendar'] = keepCalendar;
    body['sendAssignReceiver'] = sendAssignReceiver;
    if (startTime != null) body['startTime'] = startTime.toISOFormatString();
    body['priority'] = _priority(priorityValue, priorityText);

    return _execute(
      method: ApiHttpMethod.post,
      path: '/mail/send',
      queryParameters: query,
      body: jsonEncode(body),
      operation: 'postMailSend',
    );
  }

  /// Speichert Anhänge einer E-Mail in der Datenbank.
  ///
  /// Ruft `POST v1/mail/saveAttachmentsToDB/{mailOid}` auf und übernimmt
  /// ausgewählte oder alle Anhänge in DOCUframe.
  ///
  /// [mailOid] - OID der Quell-E-Mail
  /// [saveAll] - Alle Anhänge speichern
  /// [extractSingularZipFile] - Eine einzelne ZIP-Datei beim Speichern entpacken
  /// [indices] - Indizes der Anhänge, die gespeichert werden sollen
  ///
  /// Returns: [RestApiResponse] mit dem Ergebnis des Speichervorgangs
  Future<RestApiResponse> saveMailAttachmentsToDatabase(
    String mailOid, {
    bool saveAll = false,
    bool extractSingularZipFile = false,
    List<int> indices = const <int>[],
  }) {
    return _execute(
      method: ApiHttpMethod.post,
      path: '/mail/saveAttachmentsToDB/$mailOid',
      body: jsonEncode(<String, dynamic>{
        'saveAll': saveAll,
        'extractSingularZipFile': extractSingularZipFile,
        'indices': indices,
      }),
      operation: 'saveMailAttachmentsToDatabase',
    );
  }

  /// not implemented in df-restapi
  ///
  /// This request allows to reply for an email
  ///
  /// Hinweis zur neuen API:
  /// Beantwortet eine E-Mail (`POST v1/mail/reply/{sourceMailOid}`).
  ///
  /// Serverseitig (noch) nicht implementiert; der Client-Vertrag bleibt exakt
  /// erhalten.
  Future<RestApiResponse> postMailReply(
    String sourceMailOid, {
    String uuid = '',
    String oid = '',
    String from = '-',
    String to = '-',
    String cc = '-',
    String bcc = '-',
    String name = '-',
    String description = '-',
    String subject = '-',
    String htmlContent = '-',
    String plainContent = '-',
    String template = '',
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = 'normal',
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    DateTime? startTime,
    String action = '',
    String actions = '',
    String serialization = '',
    bool assignAddress = false,
    bool assignProject = false,
    bool assignProduct = false,
    bool assignContact = false,
    bool sendAssignReceiver = false,
    bool assignAction = false,
  }) {
    return _stringRecipientReply(
      path: '/mail/reply/$sourceMailOid',
      operation: 'postMailReply',
      uuid: uuid,
      oid: oid,
      from: from,
      to: to,
      cc: cc,
      bcc: bcc,
      name: name,
      description: description,
      subject: subject,
      htmlContent: htmlContent,
      plainContent: plainContent,
      template: template,
      templateData: templateData,
      attachments: attachments,
      priorityValue: priorityValue,
      priorityText: priorityText,
      acknowledgementRequired: acknowledgementRequired,
      keepCalendar: keepCalendar,
      startTime: startTime,
      action: action,
      actions: actions,
      serialization: serialization,
      assignAddress: assignAddress,
      assignProject: assignProject,
      assignProduct: assignProduct,
      assignContact: assignContact,
      sendAssignReceiver: sendAssignReceiver,
      assignAction: assignAction,
    );
  }

  /// not implemented in df-restapi
  ///
  /// This request allows to reply all for an email
  ///
  /// Hinweis zur neuen API:
  /// Beantwortet eine E-Mail an alle (`POST v1/mail/replyAll/{sourceMailOid}`).
  ///
  /// Serverseitig (noch) nicht implementiert; der Client-Vertrag bleibt exakt
  /// erhalten.
  Future<RestApiResponse> postMailReplyAll(
    String sourceMailOid, {
    String uuid = '',
    String oid = '',
    String from = '-',
    String to = '-',
    String cc = '-',
    String bcc = '-',
    String name = '-',
    String description = '-',
    String subject = '-',
    String htmlContent = '-',
    String plainContent = '-',
    String template = '',
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = 'normal',
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    DateTime? startTime,
    String action = '',
    String actions = '',
    String serialization = '',
    bool assignAddress = false,
    bool assignProject = false,
    bool assignProduct = false,
    bool assignContact = false,
    bool sendAssignReceiver = false,
    bool assignAction = false,
  }) {
    return _stringRecipientReply(
      path: '/mail/replyAll/$sourceMailOid',
      operation: 'postMailReplyAll',
      uuid: uuid,
      oid: oid,
      from: from,
      to: to,
      cc: cc,
      bcc: bcc,
      name: name,
      description: description,
      subject: subject,
      htmlContent: htmlContent,
      plainContent: plainContent,
      template: template,
      templateData: templateData,
      attachments: attachments,
      priorityValue: priorityValue,
      priorityText: priorityText,
      acknowledgementRequired: acknowledgementRequired,
      keepCalendar: keepCalendar,
      startTime: startTime,
      action: action,
      actions: actions,
      serialization: serialization,
      assignAddress: assignAddress,
      assignProject: assignProject,
      assignProduct: assignProduct,
      assignContact: assignContact,
      sendAssignReceiver: sendAssignReceiver,
      assignAction: assignAction,
    );
  }

  /// not implemented in df-restapi
  ///
  /// This request allows to forward an email
  ///
  /// Hinweis zur neuen API:
  /// Leitet eine E-Mail weiter (`POST v1/mail/forward/{sourceMailOid}`).
  ///
  /// Serverseitig (noch) nicht implementiert; der Client-Vertrag bleibt exakt
  /// erhalten. Anders als reply/replyAll sind to/cc/bcc hier Listen und werden
  /// nur bei Nicht-null gesendet.
  Future<RestApiResponse> postMailForward(
    String sourceMailOid, {
    String uuid = '',
    String oid = '',
    String from = '-',
    List<String>? to,
    List<String>? cc,
    List<String>? bcc,
    String name = '-',
    String description = '-',
    String subject = '-',
    String htmlContent = '-',
    String plainContent = '-',
    String template = '',
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = 'normal',
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    DateTime? startTime,
    String action = '',
    String actions = '',
    String serialization = '',
    bool assignAddress = false,
    bool assignProject = false,
    bool assignProduct = false,
    bool assignContact = false,
    bool sendAssignReceiver = false,
    bool assignAction = false,
  }) {
    final Map<String, String> query = _actionsQuery(
      action,
      actions,
      serialization,
    );

    final Map<String, dynamic> body = <String, dynamic>{
      '~UUID': uuid,
      '~ObjectID': oid,
      'from': from,
    };
    if (to != null) body['to'] = to;
    if (cc != null) body['cc'] = cc;
    if (bcc != null) body['bcc'] = bcc;
    body['name'] = name;
    body['description'] = description;
    body['subject'] = subject;
    body['htmlContent'] = htmlContent;
    body['plainContent'] = plainContent;
    if (template != '') body['template'] = template;
    if (templateData != null) body['templateData'] = templateData;
    if (attachments != null) body['attachments'] = attachments;
    body['acknowledgementRequired'] = acknowledgementRequired;
    body['keepCalendar'] = keepCalendar;
    if (startTime != null) body['startTime'] = startTime.toISOFormatString();
    body['priority'] = _priority(priorityValue, priorityText);
    _addAssignments(
      body,
      assignAddress: assignAddress,
      assignProject: assignProject,
      assignProduct: assignProduct,
      assignContact: assignContact,
      assignAction: assignAction,
      sendAssignReceiver: sendAssignReceiver,
    );

    return _execute(
      method: ApiHttpMethod.post,
      path: '/mail/forward/$sourceMailOid',
      queryParameters: query,
      body: jsonEncode(body),
      operation: 'postMailForward',
    );
  }

  /// Ruft die verfügbaren E-Mail-Konten des angemeldeten Benutzers ab.
  ///
  /// Verwendet `GET v1/mail/accounts`.
  ///
  /// Returns: [RestApiResponse] mit den konfigurierten E-Mail-Konten
  Future<RestApiResponse> getMailAccounts() {
    return _execute(
      method: ApiHttpMethod.get,
      path: '/mail/accounts',
      operation: 'getMailAccounts',
    );
  }

  /// Ruft die E-Mail-Signaturen des angemeldeten Benutzers ab.
  ///
  /// Verwendet `GET v1/userEmailSignatures`.
  ///
  /// Returns: [RestApiResponse] mit den verfügbaren Signaturen
  Future<RestApiResponse> getUserEmailSignatures() {
    return _execute(
      method: ApiHttpMethod.get,
      path: '/userEmailSignatures',
      operation: 'getUserEmailSignatures',
    );
  }

  /// Gemeinsamer Body-/Wire-Aufbau für reply und replyAll (String-Empfänger,
  /// stets vorhanden; identisch bis auf den Pfad).
  Future<RestApiResponse> _stringRecipientReply({
    required String path,
    required String operation,
    required String uuid,
    required String oid,
    required String from,
    required String to,
    required String cc,
    required String bcc,
    required String name,
    required String description,
    required String subject,
    required String htmlContent,
    required String plainContent,
    required String template,
    required Map<String, dynamic>? templateData,
    required List<Map<String, dynamic>>? attachments,
    required int priorityValue,
    required String priorityText,
    required bool acknowledgementRequired,
    required bool keepCalendar,
    required DateTime? startTime,
    required String action,
    required String actions,
    required String serialization,
    required bool assignAddress,
    required bool assignProject,
    required bool assignProduct,
    required bool assignContact,
    required bool sendAssignReceiver,
    required bool assignAction,
  }) {
    final Map<String, String> query = _actionsQuery(
      action,
      actions,
      serialization,
    );

    final Map<String, dynamic> body = <String, dynamic>{
      '~UUID': uuid,
      '~ObjectID': oid,
      'from': from,
      'to': to,
      'cc': cc,
      'bcc': bcc,
      'name': name,
      'description': description,
      'subject': subject,
      'htmlContent': htmlContent,
      'plainContent': plainContent,
    };
    if (template != '') body['template'] = template;
    if (templateData != null) body['templateData'] = templateData;
    if (attachments != null) body['attachments'] = attachments;
    body['acknowledgementRequired'] = acknowledgementRequired;
    body['keepCalendar'] = keepCalendar;
    if (startTime != null) body['startTime'] = startTime.toISOFormatString();
    body['priority'] = _priority(priorityValue, priorityText);
    _addAssignments(
      body,
      assignAddress: assignAddress,
      assignProject: assignProject,
      assignProduct: assignProduct,
      assignContact: assignContact,
      assignAction: assignAction,
      sendAssignReceiver: sendAssignReceiver,
    );

    return _execute(
      method: ApiHttpMethod.post,
      path: path,
      queryParameters: query,
      body: jsonEncode(body),
      operation: operation,
    );
  }

  Map<String, dynamic> _priority(int priorityValue, String priorityText) {
    return <String, dynamic>{
      'priorityValue': priorityValue,
      'priorityText': priorityText,
    };
  }

  Map<String, String> _actionsQuery(
    String action,
    String actions,
    String serialization,
  ) {
    final Map<String, String> query = <String, String>{};
    if (action.isNotEmpty) query['action'] = action;
    if (actions.isNotEmpty) query['actions'] = actions;
    if (serialization.isNotEmpty) query['serialization'] = serialization;
    return query;
  }

  void _addAssignments(
    Map<String, dynamic> body, {
    required bool assignAddress,
    required bool assignProject,
    required bool assignProduct,
    required bool assignContact,
    required bool assignAction,
    required bool sendAssignReceiver,
  }) {
    body['assignAddresses'] = assignAddress;
    body['assignProjects'] = assignProject;
    body['assignProducts'] = assignProduct;
    body['assignContacts'] = assignContact;
    body['assignActions'] = assignAction;
    body['sendAssignReceiver'] = sendAssignReceiver;
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
        operationId: 'v1.mail.$operation',
      ),
    );
  }
}
