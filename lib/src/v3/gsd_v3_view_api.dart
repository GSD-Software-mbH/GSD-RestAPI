import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/v3/gsd_view_action_request.dart';
import 'package:gsd_restapi/src/models/v3/gsd_view_load_request.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/body_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:meta/meta.dart';

/// Native V3-Viewoperationen.
class GsdV3ViewApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV3ViewApi.internal(this._runtime);
  static const DataResponsePolicy<List<Object?>> _loadPolicy =
      DataResponsePolicy<List<Object?>>();
  static const BodyResponsePolicy _actionPolicy = BodyResponsePolicy();

  final ApiRuntime _runtime;

  /// Lädt Views über `POST v3/view/load`.
  ///
  /// Gibt das `data`-Array der Antwort zurück, einen Eintrag je Eintrag in
  /// [requests], in derselben Reihenfolge.
  Future<List<Object?>> load(List<GsdViewLoadRequest> requests) => _post(
    '/view/load',
    jsonEncode([for (final request in requests) request.toJson()]),
    'v3.view.load',
    _loadPolicy,
  );

  /// Führt eine View-Aktion über `POST v3/view/action` aus.
  ///
  /// Gibt den ganzen Body der Antwort zurück: Neben `data` (etwa
  /// `clientDirective`) stehen oben `objectId` und `object`.
  Future<Map<String, Object?>> action(GsdViewActionRequest request) => _post(
    '/view/action',
    jsonEncode(request.toJson()),
    'v3.view.action',
    _actionPolicy,
  );

  Future<T> _post<T>(
    String path,
    String body,
    String operationId,
    IResponsePolicy<T> responsePolicy,
  ) {
    return _runtime.execute(
      ApiRequest<T>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v3,
        path: path,
        body: body,
        authentication: AuthenticationPolicy.session,
        responsePolicy: responsePolicy,
        operationId: operationId,
      ),
    );
  }
}
