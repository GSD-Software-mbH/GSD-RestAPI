import 'dart:async';

import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/v1/v1_requester.dart';
import 'package:meta/meta.dart';

/// Native persönliche V1-Operationen für den angemeldeten Benutzer.
class GsdV1PersonalApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1PersonalApi.internal(this._runtime);
  late final V1Requester _requests = V1Requester(_runtime, 'personal');

  final ApiRuntime _runtime;

  /// Ruft ungelesene Dokumente des aktuellen Benutzers ab
  ///
  /// Lädt alle Dokumente, die vom aktuellen Benutzer noch nicht gelesen wurden.
  /// Hilfreich für Benachrichtigungen und To-Do-Listen.
  ///
  /// Returns: `data` der Antwort mit der Liste ungelesener Dokumente
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.personal.getPersonalUnreadDocuments()
  ///     as Map<String, Object?>;
  /// List unreadDocs = data['documents'] as List;
  /// print("${unreadDocs.length} ungelesene Dokumente");
  /// ```
  Future<Object?> getPersonalUnreadDocuments() => _requests.execute(
    method: GsdHttpMethod.get,
    path: '/personal/unreadDocuments',
    operation: 'unreadDocuments',
  );

  /// Ruft persönliche Aufgaben des aktuellen Benutzers ab
  ///
  /// Lädt alle dem aktuellen Benutzer zugewiesenen Aufgaben und Aktionen.
  /// Enthält sowohl offene als auch abgeschlossene Aufgaben.
  ///
  /// Returns: `data` der Antwort mit der Liste persönlicher Aufgaben
  ///
  /// Beispiel:
  /// ```dart
  /// final data =
  ///     await api.v1.personal.getPersonalMyTasks() as Map<String, Object?>;
  /// List tasks = data['tasks'] as List;
  /// print("${tasks.length} Aufgaben gefunden");
  /// ```
  Future<Object?> getPersonalMyTasks() => _requests.execute(
    method: GsdHttpMethod.get,
    path: '/personal/myTasks',
    operation: 'myTasks',
  );

  /// Leert den Papierkorb des aktuellen Benutzers
  ///
  /// Löscht alle Objekte aus dem persönlichen Papierkorb endgültig.
  /// Diese Aktion kann nicht rückgängig gemacht werden.
  ///
  /// Returns: `data` der Antwort mit dem Status der Papierkorb-Leerung
  ///
  /// Beispiel:
  /// ```dart
  /// final data =
  ///     await api.v1.personal.patchPersonalEmptyRecycleBin();
  /// print("Papierkorb erfolgreich geleert");
  /// ```
  Future<Object?> patchPersonalEmptyRecycleBin() => _requests.execute(
    method: GsdHttpMethod.patch,
    path: '/personal/emptyRecycleBin',
    operation: 'emptyRecycleBin',
  );
}
