part of '../../../docuframe_api.dart';

/// Native Konto-Operationen der V1-Fassade.
class V1AccountApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1AccountApi.internal(this._runtime);

  /// Erstellt ein Demo-Benutzerkonto für Testzwecke
  ///
  /// Legt ein temporäres Demo-Konto mit den angegebenen Anmeldedaten an.
  /// Wird hauptsächlich für Demonstrations- und Testzwecke verwendet.
  ///
  /// [password] - Das Passwort für das Demo-Konto (wird als MD5-Hash gespeichert)
  ///
  /// Returns: [RestApiResponse] mit dem Status der Konto-Erstellung
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.account.createDemoAccount("demo123");
  /// if (response.isOk) {
  ///   print("Demo-Konto erfolgreich erstellt");
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Legt einen Demo-Benutzer an (`POST v1/DF/CreateDemoUser`).
  ///
  /// Der Body enthält die konfigurierte `deviceId` und das übergebene
  /// [password].
  Future<RestApiResponse> createDemoAccount(String password) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.post,
        version: ApiVersion.v1,
        path: '/DF/CreateDemoUser',
        body: jsonEncode(<String, dynamic>{
          'deviceId': _runtime.configuration.device?.deviceId,
          'password': password,
        }),
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v1.account.createDemoAccount',
      ),
    );
  }
}
