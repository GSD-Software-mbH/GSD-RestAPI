import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/gsd_sync_container.dart';
import 'package:gsd_restapi/src/models/gsd_sync_objects_result.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/deduplication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/model_response_policy.dart';
import 'package:meta/meta.dart';

/// Native Synchronisationsoperationen unter `v1/xSync`.
class GsdV1XSyncApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1XSyncApi.internal(this._runtime);
  static const DataResponsePolicy<Object?> _responsePolicy =
      DataResponsePolicy<Object?>();
  static const ModelResponsePolicy<GsdSyncObjectsResult>
  _syncObjectsResponsePolicy = ModelResponsePolicy<GsdSyncObjectsResult>(
    GsdSyncObjectsResult.fromJson,
  );

  final ApiRuntime _runtime;

  /// Ruft Synchronisations-Klassen-Informationen für eine Anwendung ab.
  ///
  /// Lädt die verfügbaren Synchronisations-Klassen und deren Metadaten für
  /// eine bestimmte Anwendung. Die Informationen beschreiben die für xSync
  /// verfügbaren Datenstrukturen und Eigenschaften.
  ///
  /// [appName] - Name der Anwendung, deren Klassen abgerufen werden
  ///
  /// Returns: `data` der Antwort mit den Klasseninformationen
  ///
  /// Throws: GsdHttpException bei HTTP-Fehlern
  /// Throws: GsdSessionInvalidException bei ungültiger Session
  Future<Object?> getSyncClassInfo(String appName) {
    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v1,
        path: '/xSync/ClassInfo/$appName',
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _responsePolicy,
        operationId: 'v1.xSync.getSyncClassInfo',
      ),
    );
  }

  /// Ruft Synchronisations-Objekte einer bestimmten Klasse ab.
  ///
  /// Lädt die aktuellen Daten und Metadaten der angegebenen xSync-Klasse.
  /// Bereits bekannte Containerstände können mitgegeben werden, um nur die
  /// nachfolgenden Datensätze abzurufen.
  ///
  /// [appName] - Name der Anwendung
  /// [className] - Name der abzurufenden Synchronisations-Klasse
  /// [nextContainers] - Zuletzt bekannte Marker und Revisionen je Container
  /// [maxRecords] - Optionale maximale Anzahl zurückgegebener Datensätze
  ///
  /// Returns: [GsdSyncObjectsResult] mit den synchronisierten Objektdaten
  ///
  /// Throws: GsdHttpException bei HTTP-Fehlern
  /// Throws: GsdSessionInvalidException bei ungültiger Session
  Future<GsdSyncObjectsResult> getSyncObjectsOfClass(
    String appName,
    String className, {
    List<GsdSyncContainer> nextContainers = const [],
    int? maxRecords,
  }) {
    final bodyMap = <String, dynamic>{};

    if (maxRecords != null) {
      bodyMap['maxRecords'] = maxRecords;
    }

    for (final container in nextContainers) {
      bodyMap[container.containerId] = <String, dynamic>{
        'lastMarker': container.nextMarker,
        'revision': container.revision,
      };
    }

    return _runtime.execute(
      ApiRequest<GsdSyncObjectsResult>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v1,
        path: '/xSync/dynamic/$appName/$className',
        body: bodyMap.isNotEmpty ? jsonEncode(bodyMap) : null,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _syncObjectsResponsePolicy,
        operationId: 'v1.xSync.getSyncObjectsOfClass',
      ),
    );
  }
}
