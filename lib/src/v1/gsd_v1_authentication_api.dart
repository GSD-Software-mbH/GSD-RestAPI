import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/gsd_login_result.dart';
import 'package:gsd_restapi/src/models/gsd_two_factor_secret.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/deduplication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/model_response_policy.dart';
import 'package:gsd_restapi/src/runtime/session/session_coordinator.dart';
import 'package:meta/meta.dart';

/// Native Authentifizierungsoperationen der neuen V1-Fassade.
///
/// Der Login verwendet aus Kompatibilitätsgründen den bestehenden
/// verschlüsselten `v2/login`-Wire-Vertrag. Die Gruppierung unter `v1`
/// bezeichnet die öffentliche API-Familie, nicht das URL-Präfix dieses
/// technischen Login-Endpunkts.
class GsdV1AuthenticationApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1AuthenticationApi.internal(this._runtime, this._sessionCoordinator);
  static const DataResponsePolicy<Object?> _responsePolicy =
      DataResponsePolicy<Object?>();
  static const ModelResponsePolicy<GsdTwoFactorSecret>
  _twoFactorSecretResponsePolicy = ModelResponsePolicy<GsdTwoFactorSecret>(
    GsdTwoFactorSecret.fromJson,
  );

  final ApiRuntime _runtime;
  final SessionCoordinator _sessionCoordinator;

  /// Meldet den Benutzer in der Datenbank über '/v2/login' oder '/v2/login/secure' an
  ///
  /// Führt eine sichere Anmeldung mit RSA- oder AES-Verschlüsselung durch.
  /// Die Methode verwendet entweder v2/login (mit AES) oder v2/login/secure (mit RSA)
  /// je nach der Konfiguration der `v2Login`-Eigenschaft.
  ///
  /// [md5Password] - Das bereits als MD5-Hash verschlüsselte Passwort
  ///
  /// Returns: [GsdLoginResult] mit Session-ID, Anwendungen und Benutzer
  ///
  /// Throws: die `GsdApiException` zum Status, etwa
  /// `GsdInvalidCredentialsException` oder
  /// `GsdTwoFactorTokenMissingException`; `GsdParseException`, wenn
  /// `data.sessionId` fehlt
  ///
  /// Beispiel:
  /// ```dart
  /// String hashedPassword = "098f6bcd4621d373cade4e832627b4f6"; // MD5 von "test"
  /// final GsdLoginResult result =
  ///     await api.v1.authentication.login(hashedPassword);
  /// print("Anmeldung erfolgreich: ${result.sessionId}");
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Meldet den in der Konfiguration angegebenen Benutzer an.
  ///
  /// [md5Password] muss bereits als MD5-Hash vorliegen. Ein Klartextpasswort
  /// wird bewusst nicht automatisch gehasht.
  Future<GsdLoginResult> login(
    String md5Password, {
    String? twoFactorAuthToken,
  }) {
    return _sessionCoordinator.login(
      md5Password,
      twoFactorAuthToken: twoFactorAuthToken,
    );
  }

  /// Hinterlegt das bereits MD5-gehashte Passwort für die automatische
  /// Anmeldung bzw. Erneuerung einer z.B. beim App-Start geladenen Session.
  ///
  /// Dies ist das strukturierte Gegenstück zu
  /// `setPassword()` des Legacy-Managers (bis 0.2.x).
  void setPassword(String md5Password) {
    _sessionCoordinator.setPassword(md5Password);
  }

  /// Stellt eine persistierte Session wieder her. Wird [md5Password]
  /// mitgegeben, kann ein abgelaufener erster Request die Session automatisch
  /// erneuern; ohne Passwort bleibt die Session bewusst nicht refresh-fähig.
  void restoreSession(String sessionId, {String md5Password = ''}) {
    _sessionCoordinator.restoreSession(sessionId, md5Password: md5Password);
  }

  /// Meldet den Benutzer vom System ab
  ///
  /// Beendet die aktuelle Session und setzt alle Session-bezogenen
  /// Variablen zurück. Sendet eine Abmelde-Anfrage an den Server.
  ///
  /// Returns: `data` der Antwort
  ///
  /// Nach der Abmeldung werden automatisch folgende Aktionen ausgeführt:
  /// - Session-ID wird geleert
  /// - Anmeldestatus wird auf false gesetzt
  /// - sessionIdChangedEvent wird ausgelöst
  ///
  /// Beispiel:
  /// ```dart
  /// await api.v1.authentication.logout();
  /// print("Erfolgreich abgemeldet");
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Meldet die aktuelle Session ab und leert sie auch bei einem Serverfehler.
  Future<Object?> logout() => _sessionCoordinator.logout();

  /// Überprüft die aktuelle Session über '/_CheckSession'
  ///
  /// Verifiziert, ob die aktuelle Session noch gültig ist.
  /// Diese Methode sollte regelmäßig aufgerufen werden, um sicherzustellen,
  /// dass die Session nicht abgelaufen ist.
  ///
  /// Returns: `data` der Antwort
  ///
  /// Throws: die `GsdApiException` zum Status, etwa
  /// `GsdSessionInvalidException`
  ///
  /// Beispiel:
  /// ```dart
  /// try {
  ///   await api.v1.authentication.checkSession();
  ///   print("Session ist noch gültig");
  /// } catch (e) {
  ///   print("Session-Prüfung fehlgeschlagen: $e");
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Prüft die Session über den unversionierten Alias-Pfad `_CheckSession`.
  Future<Object?> checkSession() {
    return _runtime.execute(
      const ApiRequest<Object?>.unversioned(
        method: GsdHttpMethod.get,
        path: '/_CheckSession',
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _responsePolicy,
        operationId: 'v1.authentication.checkSession',
      ),
    );
  }

  /// Validiert ein 2FA-Token für eine Anwendung
  ///
  /// Überprüft, ob das angegebene 2FA-Token (TOTP) für die spezifizierte
  /// Anwendung gültig ist. Wird zur Verifikation von
  /// Zwei-Faktor-Authentifizierung verwendet.
  ///
  /// [appname] - Name der Anwendung (z.B. "GSD-DFApp")
  /// [token] - Das 6-stellige 2FA-Token vom Authenticator
  ///
  /// Returns: `data` der Antwort
  ///
  /// Throws: `GsdTwoFactorTokenInvalidException` bei einem falschen Token
  ///
  /// Beispiel:
  /// ```dart
  /// await api.v1.authentication.validate2FASecret("GSD-DFApp", "123456");
  /// print("2FA-Token ist gültig");
  /// ```
  Future<Object?> validate2FASecret(String appname, String token) {
    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v1,
        path: '/2fa/validate',
        queryParameters: <String, String>{'app': appname},
        body: jsonEncode(<String, dynamic>{'token': token}),
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v1.authentication.validate2FASecret',
      ),
    );
  }

  /// Ruft 2FA-Secret-Informationen für einen Benutzer ab
  ///
  /// Lädt die 2FA-Konfigurationsdaten für einen spezifischen Benutzer
  /// und eine Anwendung, einschließlich Aktivierungs- und Bestätigungsstatus.
  ///
  /// [appname] - Name der Anwendung (z.B. "GSD-DFApp")
  /// [username] - Benutzername für die 2FA-Abfrage
  ///
  /// Returns: [GsdTwoFactorSecret] mit 2FA-Status und Konfigurationsdaten
  ///
  /// Beispiel:
  /// ```dart
  /// final GsdTwoFactorSecret secret =
  ///     await api.v1.authentication.get2FASecret("GSD-DFApp", "mueller");
  /// bool isActivated = secret.isActivated;
  /// bool isConfirmed = secret.isConfirmed;
  /// GsdTwoFactorStatus status = secret.status;
  /// ```
  Future<GsdTwoFactorSecret> get2FASecret(
    String appname,
    String username,
  ) {
    return _runtime.execute(
      ApiRequest<GsdTwoFactorSecret>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v1,
        path: '/2fa/secret',
        queryParameters: <String, String>{'app': appname, 'username': username},
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _twoFactorSecretResponsePolicy,
        operationId: 'v1.authentication.get2FASecret',
      ),
    );
  }

  /// Erstellt ein neues 2FA-Secret für eine Anwendung
  ///
  /// Generiert ein neues TOTP-Secret für die Zwei-Faktor-Authentifizierung
  /// einer spezifischen Anwendung. Das Secret wird für die Einrichtung
  /// von Authenticator-Apps verwendet.
  ///
  /// [appname] - Name der Anwendung (z.B. "GSD-DFApp")
  ///
  /// Returns: `data` der Antwort mit dem neuen 2FA-Secret
  ///
  /// `data` enthält:
  /// - Base32-kodiertes Secret für manuelle Eingabe
  /// - QR-Code-URL für Authenticator-Apps
  /// - Backup-Codes für Notfälle
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.authentication.create2FASecret("GSD-DFApp")
  ///     as Map<String, Object?>;
  /// String secret = data['secret'] as String;
  /// ```
  Future<Object?> create2FASecret(String appname) {
    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v1,
        path: '/2fa/secret',
        queryParameters: <String, String>{'app': appname},
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v1.authentication.create2FASecret',
      ),
    );
  }

  /// Erneuert ein bestehendes 2FA-Secret
  ///
  /// Generiert ein neues TOTP-Secret für eine bereits konfigurierte
  /// 2FA-Anwendung. Erfordert ein gültiges Token zur Autorisierung.
  ///
  /// [appname] - Name der Anwendung (z.B. "GSD-DFApp")
  /// [token] - Gültiges 2FA-Token zur Autorisierung der Erneuerung
  ///
  /// Returns: `data` der Antwort mit dem neuen 2FA-Secret
  ///
  /// Nach der Erneuerung:
  /// - Das alte Secret wird ungültig
  /// - Ein neues Secret wird generiert
  /// - Authenticator-Apps müssen neu konfiguriert werden
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.authentication.refresh2FASecret(
  ///   "GSD-DFApp",
  ///   "123456",
  /// ) as Map<String, Object?>;
  /// String newSecret = data['secret'] as String;
  /// // Benutzer muss Authenticator-App neu einrichten
  /// ```
  Future<Object?> refresh2FASecret(String appname, String token) {
    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.patch,
        version: GsdApiVersion.v1,
        path: '/2fa/secret',
        queryParameters: <String, String>{'app': appname},
        body: jsonEncode(<String, dynamic>{'token': token}),
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v1.authentication.refresh2FASecret',
      ),
    );
  }

  /// Löscht ein 2FA-Secret für eine Anwendung
  ///
  /// Entfernt die 2FA-Konfiguration für eine spezifische Anwendung
  /// und deaktiviert die Zwei-Faktor-Authentifizierung.
  ///
  /// [appname] - Name der Anwendung (z.B. "GSD-DFApp")
  /// [token] - Gültiges 2FA-Token zur Autorisierung der Löschung
  ///
  /// Returns: `data` der Antwort
  ///
  /// Nach der Löschung:
  /// - 2FA wird für die Anwendung deaktiviert
  /// - Alle Backup-Codes werden ungültig
  /// - Normale Passwort-Anmeldung ist wieder möglich
  ///
  /// Beispiel:
  /// ```dart
  /// await api.v1.authentication.delete2FASecret("GSD-DFApp", "123456");
  /// print("2FA erfolgreich deaktiviert");
  /// ```
  Future<Object?> delete2FASecret(String appname, String token) {
    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.delete,
        version: GsdApiVersion.v1,
        path: '/2fa/secret',
        queryParameters: <String, String>{'app': appname},
        body: jsonEncode(<String, dynamic>{'token': token}),
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v1.authentication.delete2FASecret',
      ),
    );
  }
}
