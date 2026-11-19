import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/v3/gsd_structure_request.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:meta/meta.dart';

/// Native V3-Modelloperationen.
class GsdV3ModelApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV3ModelApi.internal(this._runtime);
  static const DataResponsePolicy<List<Object?>> _responsePolicy =
      DataResponsePolicy<List<Object?>>();

  final ApiRuntime _runtime;

  /// Lädt die Modellstruktur über `POST v3/model/structure`.
  ///
  /// Gibt das `data`-Array der Antwort zurück, mit der Struktur der in
  /// [requests] angefragten Klassen.
  Future<List<Object?>> structure(List<GsdStructureRequest> requests) {
    return _runtime.execute(
      ApiRequest<List<Object?>>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v3,
        path: '/model/structure',
        body: jsonEncode([for (final request in requests) request.toJson()]),
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v3.model.structure',
      ),
    );
  }
}
