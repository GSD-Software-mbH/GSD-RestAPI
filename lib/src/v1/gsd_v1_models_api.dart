import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/v1/v1_requester.dart';
import 'package:meta/meta.dart';

/// Native Modell-, Struktur- und Wörterbuch-Operationen der V1-Fassade.
class GsdV1ModelsApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1ModelsApi.internal(this._runtime);
  late final V1Requester _requests = V1Requester(_runtime, 'models');

  final ApiRuntime _runtime;

  /// Ruft die Modell-Struktur der Datenbank ab
  ///
  /// Lädt die Strukturinformationen für Datenbank-Klassen und deren
  /// Eigenschaften.
  /// Nützlich für dynamische UI-Generierung und Datenvalidierung.
  ///
  /// [classes] - Komma-getrennte Liste spezifischer Klassen (optional)
  /// [baseClasses] - Basis-Klassen für Vererbungshierarchie
  /// [skipMembers] - Eigenschaften überspringen (Standard: false)
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: `data` der Antwort mit Modell-Strukturdaten
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.models.getModelStructure(
  ///   classes: "Vorgang,Adresse,Projekt"
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt die Modellstruktur (`GET v1/model/structure`).
  ///
  /// `baseClasses` und `skipMembers` bleiben aus Signatur-Kompatibilität
  /// erhalten, werden aber - wie im Legacy-Manager - NICHT gesendet.
  Future<Object?> getModelStructure({
    String classes = '',
    String baseClasses = '',
    bool skipMembers = false,
    String rightsControlKey = '',
  }) {
    final query = <String, String>{};
    if (classes.isNotEmpty) query['classes'] = classes;
    if (rightsControlKey.isNotEmpty) {
      query['rightsControlKey'] = rightsControlKey;
    }
    return _requests.execute(
      method: GsdHttpMethod.get,
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
  /// Returns: `data` der Antwort mit erweiterten Modell-Strukturdaten
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.models.getExtModelStructure(
  ///   classes: "Vorgang,Adresse",
  ///   skipMembers: false
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt die erweiterte Modellstruktur (`GET v1/extModel/structure`).
  Future<Object?> getExtModelStructure({
    String classes = '',
    String baseClasses = '',
    bool skipMembers = false,
    String rightsControlKey = '',
  }) {
    final query = <String, String>{};
    if (classes.isNotEmpty) query['classes'] = classes;
    if (baseClasses.isNotEmpty) query['baseClasses'] = baseClasses;
    if (skipMembers) query['skipMembers'] = skipMembers.toString();
    if (rightsControlKey.isNotEmpty) {
      query['rightsControlKey'] = rightsControlKey;
    }
    return _requests.execute(
      method: GsdHttpMethod.get,
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
  /// Returns: `data` der Antwort mit ML-spezifischen Modell-Daten
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.models.getExtModelML(
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
  Future<Object?> getExtModelML({
    List<String>? headerClasses,
    List<String>? bodyClasses,
    bool skipMembers = false,
  }) {
    final query = <String, String>{};
    if (headerClasses != null && headerClasses.isNotEmpty) {
      query['ml'] = jsonEncode(headerClasses);
    }
    if (skipMembers) query['skipMembers'] = skipMembers.toString();

    final isPost = bodyClasses != null;
    String? body;
    if (isPost) {
      body = bodyClasses.isNotEmpty
          ? jsonEncode(<String, dynamic>{'ml': bodyClasses})
          : '';
    }

    return _requests.execute(
      method: isPost ? GsdHttpMethod.post : GsdHttpMethod.get,
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
  /// Returns: `data` der Antwort mit Index-Informationen und Performance-Daten
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.models.getExtModelIndexes(
  ///   classes: "Vorgang,Adresse"
  /// ) as Map<String, Object?>;
  /// List indexes = data['indexes'] as List;
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt Datenbank-Index-Informationen (`GET v1/extModel/indexes`).
  Future<Object?> getExtModelIndexes({
    String classes = '',
    String rightsControlKey = '',
  }) {
    final query = <String, String>{};
    if (classes.isNotEmpty) query['classes'] = classes;
    if (rightsControlKey.isNotEmpty) {
      query['rightsControlKey'] = rightsControlKey;
    }
    return _requests.execute(
      method: GsdHttpMethod.get,
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
  /// Returns: `data` der Antwort mit Wörterbuch-Daten und Übersetzungen
  ///
  /// Beispiel:
  /// ```dart
  /// final translations = await api.v1.models.getModelDict(
  ///   "status_labels",
  ///   langID: "de-DE"
  /// ) as Map<String, Object?>;
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt Wörterbuch-Daten (`GET v1/model/dict`); [dict] wird immer gesendet.
  Future<Object?> getModelDict(
    String dict, {
    String langID = '',
    String rightsControlKey = '',
  }) {
    final query = <String, String>{'dict': dict};
    if (langID.isNotEmpty) query['langID'] = langID;
    if (rightsControlKey.isNotEmpty) {
      query['rightsControlKey'] = rightsControlKey;
    }
    return _requests.execute(
      method: GsdHttpMethod.get,
      path: '/model/dict',
      queryParameters: query,
      operation: 'getModelDict',
    );
  }
}
