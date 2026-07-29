part of '../../../../docuframe_api.dart';

/// Native V2-Systemoperationen.
class V2SystemApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V2SystemApi.internal(this._runtime);

  Future<RestApiResponse> versionInfo() =>
      _get('/versionInfo', 'v2.system.versionInfo');

  Future<RestApiResponse> appConfig() =>
      _get('/appConfig', 'v2.system.appConfig');

  Future<RestApiResponse> appTheme() => _get('/appTheme', 'v2.system.appTheme');

  Future<RestApiResponse> _get(String path, String operationId) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v2,
        path: path,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: operationId,
      ),
    );
  }
}
