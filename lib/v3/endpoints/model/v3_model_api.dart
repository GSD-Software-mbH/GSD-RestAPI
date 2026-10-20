part of '../../../../docuframe_api.dart';

/// Native V3-Modelloperationen.
class V3ModelApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V3ModelApi.internal(this._runtime);

  /// Lädt die Modellstruktur über `POST v3/model/structure`.
  ///
  /// Der Body bleibt bis zur Stabilisierung des V3-Schemas optionales rohes
  /// JSON. Die Methode legt trotzdem Verb, Pfad, Session und Responsevertrag
  /// nativ fest.
  Future<RestApiResponse> structure({String? body}) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.post,
        version: ApiVersion.v3,
        path: '/model/structure',
        body: body,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v3.model.structure',
      ),
    );
  }
}
