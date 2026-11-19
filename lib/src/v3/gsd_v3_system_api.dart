import 'dart:async';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:meta/meta.dart';

/// Native V3-Systemoperationen.
class GsdV3SystemApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV3SystemApi.internal(this._runtime);
  static const DataResponsePolicy<Map<String, Object?>> _objectPolicy =
      DataResponsePolicy<Map<String, Object?>>();
  static const DataResponsePolicy<List<Object?>> _listPolicy =
      DataResponsePolicy<List<Object?>>();

  final ApiRuntime _runtime;

  /// Lädt die Versionsinformationen über `GET v3/versionInfo`.
  ///
  /// Gibt das `data`-Objekt der Antwort zurück.
  Future<Map<String, Object?>> versionInfo() =>
      _get('/versionInfo', 'v3.system.versionInfo', _objectPolicy);

  /// Lädt die App-Konfiguration über `GET v3/appConfig`.
  ///
  /// Gibt das `data`-Array der Antwort zurück, einen Eintrag je App
  /// (`appName`).
  Future<List<Object?>> appConfig() =>
      _get('/appConfig', 'v3.system.appConfig', _listPolicy);

  /// Lädt das App-Theme über `GET v3/appTheme`.
  ///
  /// Gibt das `data`-Array der Antwort zurück, einen Eintrag je App
  /// (`appName`).
  Future<List<Object?>> appTheme() =>
      _get('/appTheme', 'v3.system.appTheme', _listPolicy);

  Future<T> _get<T>(
    String path,
    String operationId,
    IResponsePolicy<T> responsePolicy,
  ) {
    return _runtime.execute(
      ApiRequest<T>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v3,
        path: path,
        authentication: AuthenticationPolicy.session,
        responsePolicy: responsePolicy,
        operationId: operationId,
      ),
    );
  }
}
