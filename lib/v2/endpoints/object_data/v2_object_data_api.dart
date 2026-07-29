part of '../../../../docuframe_api.dart';

/// Native V2-Objektdatenoperationen.
class V2ObjectDataApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V2ObjectDataApi.internal(this._runtime);

  Future<RestApiResponse> getById({String? body}) =>
      _post('/objectdata/byid', body, 'v2.objectData.getById');

  Future<RestApiResponse> getByQuery({String? body}) =>
      _post('/objectdata/byQuery', body, 'v2.objectData.getByQuery');

  Future<RestApiResponse> getByParentObject({String? body}) => _post(
    '/objectdata/byParentObject',
    body,
    'v2.objectData.getByParentObject',
  );

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
