import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/v3/gsd_objects_by_id_request.dart';
import 'package:gsd_restapi/src/models/v3/gsd_objects_by_parent_request.dart';
import 'package:gsd_restapi/src/models/v3/gsd_objects_by_query_request.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:meta/meta.dart';

/// Native V3-Objektdatenoperationen.
///
/// Jede Methode gibt das `data`-Array der Antwort zurück, einen Block je
/// Klasse.
class GsdV3ObjectDataApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV3ObjectDataApi.internal(this._runtime);
  static const DataResponsePolicy<List<Object?>> _responsePolicy =
      DataResponsePolicy<List<Object?>>();

  final ApiRuntime _runtime;

  /// Lädt Objektdaten per ID über `POST v3/objectdata/byid`.
  Future<List<Object?>> getById(List<GsdObjectsByIdRequest> requests) => _post(
    '/objectdata/byid',
    [for (final request in requests) request.toJson()],
    'v3.objectData.getById',
  );

  /// Lädt Objektdaten per Abfrage über `POST v3/objectdata/byQuery`.
  Future<List<Object?>> getByQuery(List<GsdObjectsByQueryRequest> requests) =>
      _post(
        '/objectdata/byQuery',
        [for (final request in requests) request.toJson()],
        'v3.objectData.getByQuery',
      );

  /// Lädt Objektdaten zu einem Elternobjekt über
  /// `POST v3/objectdata/byParentObject`.
  ///
  /// Mit `idList: true` trägt jeder Block statt Feldern und Werten nur die
  /// IDs (`ids`).
  Future<List<Object?>> getByParentObject(
    List<GsdObjectsByParentRequest> requests,
  ) => _post(
    '/objectdata/byParentObject',
    [for (final request in requests) request.toJson()],
    'v3.objectData.getByParentObject',
  );

  Future<List<Object?>> _post(
    String path,
    List<Map<String, Object?>> body,
    String operationId,
  ) {
    return _runtime.execute(
      ApiRequest<List<Object?>>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v3,
        path: path,
        body: jsonEncode(body),
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: operationId,
      ),
    );
  }
}
