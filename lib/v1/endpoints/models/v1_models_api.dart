part of '../../../docuframe_api.dart';

/// Native Modell-, Struktur- und Wörterbuch-Operationen der V1-Fassade.
class V1ModelsApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1ModelsApi.internal(this._runtime);

  /// Ruft die Modell-Struktur der Datenbank ab
  ///
  /// Lädt die Strukturinformationen für Datenbank-Klassen und deren Eigenschaften.
  /// Nützlich für dynamische UI-Generierung und Datenvalidierung.
  ///
  /// [classes] - Komma-getrennte Liste spezifischer Klassen (optional)
  /// [baseClasses] - Basis-Klassen für Vererbungshierarchie
  /// [skipMembers] - Eigenschaften überspringen (Standard: false)
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit Modell-Strukturdaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.models.getModelStructure(
  ///   classes: "Vorgang,Adresse,Projekt"
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt die Modellstruktur (`GET v1/model/structure`).
  ///
  /// `baseClasses` und `skipMembers` bleiben aus Signatur-Kompatibilität
  /// erhalten, werden aber - wie im Legacy-Manager - NICHT gesendet.
  Future<RestApiResponse> getModelStructure({
    String classes = '',
    String baseClasses = '',
    bool skipMembers = false,
    String rightsControlKey = '',
  }) {
    final Map<String, String> query = <String, String>{};
    if (classes.isNotEmpty) query['classes'] = classes;
    if (rightsControlKey.isNotEmpty) {
      query['rightsControlKey'] = rightsControlKey;
    }
    return _execute(
      method: ApiHttpMethod.get,
      path: '/model/structure',
      queryParameters: query,
      operation: 'getModelStructure',
    );
  }

  /// Ruft erweiterte Modell-Strukturinformationen ab
  ///
  /// Lädt detaillierte Strukturinformationen für das erweiterte Datenmodell
  /// mit konfigurierbaren Optionen für Klassen und Member-Daten.
  ///
  /// [classes] - Komma-getrennte Liste spezifischer Klassen (optional)
  /// [baseClasses] - Basis-Klassen für Vererbungshierarchie
  /// [skipMembers] - Member-Eigenschaften überspringen (Standard: false)
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit erweiterten Modell-Strukturdaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.models.getExtModelStructure(
  ///   classes: "Vorgang,Adresse",
  ///   skipMembers: false
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt die erweiterte Modellstruktur (`GET v1/extModel/structure`).
  Future<RestApiResponse> getExtModelStructure({
    String classes = '',
    String baseClasses = '',
    bool skipMembers = false,
    String rightsControlKey = '',
  }) {
    final Map<String, String> query = <String, String>{};
    if (classes.isNotEmpty) query['classes'] = classes;
    if (baseClasses.isNotEmpty) query['baseClasses'] = baseClasses;
    if (skipMembers) query['skipMembers'] = skipMembers.toString();
    if (rightsControlKey.isNotEmpty) {
      query['rightsControlKey'] = rightsControlKey;
    }
    return _execute(
      method: ApiHttpMethod.get,
      path: '/extModel/structure',
      queryParameters: query,
      operation: 'getExtModelStructure',
    );
  }

  /// Ruft Machine Learning Modell-Daten ab
  ///
  /// Lädt spezialisierte Datenstrukturen für Machine Learning Anwendungen
  /// mit flexibler Konfiguration über Header- und Body-Parameter.
  ///
  /// [headerClasses] - Klassen für Header-Parameter (Query-String)
  /// [bodyClasses] - Klassen für Request-Body (POST-Parameter)
  /// [skipMembers] - Member-Eigenschaften überspringen (Standard: false)
  ///
  /// Returns: [RestApiResponse] mit ML-spezifischen Modell-Daten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.models.getExtModelML(
  ///   headerClasses: ["Vorgang"],
  ///   bodyClasses: ["Adresse", "Projekt"],
  ///   skipMembers: true
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt ML-Modelldaten (`v1/extModel/ml`).
  ///
  /// Das Verb hängt von [bodyClasses] ab: `null` -> GET (nur Query), sonst
  /// POST mit `{ml: bodyClasses}`. [headerClasses] wird bei Nicht-null/Nicht-
  /// leer als `ml`-Query (JSON-kodiert) gesendet.
  Future<RestApiResponse> getExtModelML({
    List<String>? headerClasses,
    List<String>? bodyClasses,
    bool skipMembers = false,
  }) {
    final Map<String, String> query = <String, String>{};
    if (headerClasses != null && headerClasses.isNotEmpty) {
      query['ml'] = jsonEncode(headerClasses);
    }
    if (skipMembers) query['skipMembers'] = skipMembers.toString();

    final bool isPost = bodyClasses != null;
    String? body;
    if (isPost) {
      body = bodyClasses.isNotEmpty
          ? jsonEncode(<String, dynamic>{'ml': bodyClasses})
          : '';
    }

    return _execute(
      method: isPost ? ApiHttpMethod.post : ApiHttpMethod.get,
      path: '/extModel/ml',
      queryParameters: query,
      body: body,
      operation: 'getExtModelML',
    );
  }

  /// Ruft Datenbank-Index-Informationen ab
  ///
  /// Lädt Informationen über verfügbare Datenbank-Indizes für bessere
  /// Performance-Optimierung und Abfrage-Planung.
  ///
  /// [classes] - Komma-getrennte Liste spezifischer Klassen (optional)
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit Index-Informationen und Performance-Daten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.models.getExtModelIndexes(
  ///   classes: "Vorgang,Adresse"
  /// );
  /// if (response.isOk) {
  ///   List indexes = response.data['indexes'];
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt Datenbank-Index-Informationen (`GET v1/extModel/indexes`).
  Future<RestApiResponse> getExtModelIndexes({
    String classes = '',
    String rightsControlKey = '',
  }) {
    final Map<String, String> query = <String, String>{};
    if (classes.isNotEmpty) query['classes'] = classes;
    if (rightsControlKey.isNotEmpty) {
      query['rightsControlKey'] = rightsControlKey;
    }
    return _execute(
      method: ApiHttpMethod.get,
      path: '/extModel/indexes',
      queryParameters: query,
      operation: 'getExtModelIndexes',
    );
  }

  /// Ruft Wörterbuch-Daten aus dem Modell ab
  ///
  /// Lädt sprachspezifische Wörterbuch-Daten für Übersetzungen und
  /// lokalisierte Bezeichnungen innerhalb der Anwendung.
  ///
  /// [dict] - Name des anzufragenden Wörterbuchs
  /// [langID] - Sprach-ID für spezifische Lokalisierung (optional)
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit Wörterbuch-Daten und Übersetzungen
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.models.getModelDict(
  ///   "status_labels",
  ///   langID: "de-DE"
  /// );
  /// if (response.isOk) {
  ///   Map<String, String> translations = response.data;
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt Wörterbuch-Daten (`GET v1/model/dict`); [dict] wird immer gesendet.
  Future<RestApiResponse> getModelDict(
    String dict, {
    String langID = '',
    String rightsControlKey = '',
  }) {
    final Map<String, String> query = <String, String>{'dict': dict};
    if (langID.isNotEmpty) query['langID'] = langID;
    if (rightsControlKey.isNotEmpty) {
      query['rightsControlKey'] = rightsControlKey;
    }
    return _execute(
      method: ApiHttpMethod.get,
      path: '/model/dict',
      queryParameters: query,
      operation: 'getModelDict',
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
        queryParameters: (queryParameters == null || queryParameters.isEmpty)
            ? null
            : queryParameters,
        body: body,
        authentication: AuthenticationPolicy.session,
        deduplication: method == ApiHttpMethod.get
            ? DeduplicationPolicy.enabled
            : DeduplicationPolicy.disabled,
        responsePolicy: _responsePolicy,
        operationId: 'v1.models.$operation',
      ),
    );
  }
}
