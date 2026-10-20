part of '../../../../docuframe_api.dart';

/// Native V3-Objektdatenoperationen.
class V3ObjectDataApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V3ObjectDataApi.internal(this._runtime);

  Future<RestApiResponse> getById({String? body}) =>
      _post('/objectdata/byid', body, 'v3.objectData.getById');

  Future<RestApiResponse> getByQuery({String? body}) =>
      _post('/objectdata/byQuery', body, 'v3.objectData.getByQuery');

  Future<RestApiResponse> getByParentObject({String? body}) => _post(
    '/objectdata/byParentObject',
    body,
    'v3.objectData.getByParentObject',
  );

  Future<RestApiResponse> _post(String path, String? body, String operationId) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.post,
        version: ApiVersion.v3,
        path: path,
        body: body,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: operationId,
      ),
    );
  }
}
