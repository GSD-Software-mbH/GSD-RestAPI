import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:meta/meta.dart';

/// Native Konto-Operationen der V1-Fassade.
class GsdV1AccountApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1AccountApi.internal(this._runtime);
  static const DataResponsePolicy<Object?> _responsePolicy =
      DataResponsePolicy<Object?>();

  final ApiRuntime _runtime;

  /// Erstellt ein Demo-Benutzerkonto für Testzwecke
  ///
  /// Legt ein temporäres Demo-Konto mit den angegebenen Anmeldedaten an.
  /// Wird hauptsächlich für Demonstrations- und Testzwecke verwendet.
  ///
  /// [password] - Das Passwort für das Demo-Konto (wird als MD5-Hash
  ///   gespeichert)
  ///
  /// Returns: `data` der Antwort mit dem Status der Konto-Erstellung
  ///
  /// Beispiel:
  /// ```dart
  /// final data =
  ///     await api.v1.account.createDemoAccount("demo123");
  /// print("Demo-Konto erfolgreich erstellt");
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Legt einen Demo-Benutzer an (`POST v1/DF/CreateDemoUser`).
  ///
  /// Der Body enthält die konfigurierte `deviceId` und das übergebene
  /// [password].
  Future<Object?> createDemoAccount(String password) {
    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v1,
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
