part of '../../../../docuframe_api.dart';

/// Native V2-Viewoperationen.
class V2ViewApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V2ViewApi.internal(this._runtime);

  Future<RestApiResponse> load({String? body}) =>
      _post('/view/load', body, 'v2.view.load');

  Future<RestApiResponse> action({String? body}) =>
      _post('/view/action', body, 'v2.view.action');

  Future<RestApiResponse> _post(String path, String? body, String operationId) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.post,
        version: ApiVersion.v2,
        path: path,
        body: body,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: operationId,
      ),
    );
  }
}
