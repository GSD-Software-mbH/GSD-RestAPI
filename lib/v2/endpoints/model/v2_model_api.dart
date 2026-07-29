part of '../../../../docuframe_api.dart';

/// Native V2-Modelloperationen.
class V2ModelApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V2ModelApi.internal(this._runtime);

  /// Lädt die Modellstruktur über `POST v2/model/structure`.
  ///
  /// Der Body bleibt bis zur Stabilisierung des V2-Schemas optionales rohes
  /// JSON. Die Methode legt trotzdem Verb, Pfad, Session und Responsevertrag
  /// nativ fest.
  Future<RestApiResponse> structure({String? body}) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.post,
        version: ApiVersion.v2,
        path: '/model/structure',
        body: body,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v2.model.structure',
      ),
    );
  }
}
