part of '../../../../docuframe_api.dart';

/// Native V3-Systemoperationen.
class V3SystemApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V3SystemApi.internal(this._runtime);

  Future<RestApiResponse> versionInfo() =>
      _get('/versionInfo', 'v3.system.versionInfo');

  Future<RestApiResponse> appConfig() =>
      _get('/appConfig', 'v3.system.appConfig');

  Future<RestApiResponse> appTheme() => _get('/appTheme', 'v3.system.appTheme');

  Future<RestApiResponse> _get(String path, String operationId) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v3,
        path: path,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: operationId,
      ),
    );
  }
}
