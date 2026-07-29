import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_encryption/gsd_encryption.dart';
import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/raw/api_types.dart';

import '../api_request.dart';
import '../api_runtime.dart';
import '../policies/authentication_policy.dart';
import '../policies/response_policy.dart';
import '../policies/rest_api_response_policy.dart';
import '../runtime_configuration.dart';
import '../transport_response.dart';
import 'session_state.dart';

/// Koordiniert Login, Logout und Session-Refresh gegen die DOCUframe-API
/// über den neuen Runtime (nicht über den Legacy-Manager).
///
/// Der Login reproduziert den Legacy-Vertrag von
/// `RestApiDOCUframeManager.login()`/`_getv2LoginBody()` exakt:
///
/// 1. `GET v2/login/key` (ohne Session-Header, nie gepuffert) liefert den
///    öffentlichen RSA-Schlüssel des Servers (`data.key`).
/// 2. Der Klartext-Body `{user, pass, [2faToken], appNames, [device],
///    furtherencryption: false}` wird AES-verschlüsselt (IV(16) +
///    Ciphertext, Base64), der AES-Schlüssel RSA-verschlüsselt und
///    zusammen mit dem eigenen Public Key als
///    `{aesKey, data, publicKey}` an `POST v2/login` gesendet.
/// 3. Die Antwort wird über das bestehende [RestApiLoginResponse]
///    geparst; bei Erfolg wandert die Session-ID in den [SessionState].
///
/// Abweichungen vom Legacy-Manager (bewusst):
/// - Kein `loggedIn`-Zustandsflag; [hasSession] leitet sich direkt aus dem
///   [SessionState] ab (der Legacy-`loggedIn`-nach-Logout-Bug wird nicht
///   kopiert).
/// - Der Refresh-Retry nutzt ein NICHT-blockierendes `await Future.delayed`
///   und zählt Versuche korrekt. (Der Legacy-Manager nutzte ein
///   blockierendes `sleep(Duration(microseconds: 500))` und eine
///   Off-by-One-Schleife `for (i = 1; i < retryCount; i++)`, bei der aus
///   `retryCount: 3` real zwei Versuche wurden; Fehler des Logins brachen
///   die Schleife zudem sofort ab.)
@internal
class SessionCoordinator {
  /// Runtime-Konfiguration (Benutzer, App-Namen, Gerät).
  final RuntimeConfiguration configuration;

  /// Gemeinsamer Session-Zustand; wird auch vom `HeaderProvider` des
  /// angebundenen [ApiRuntime] gelesen.
  final SessionState sessionState;

  /// Wartezeit zwischen zwei Refresh-Versuchen (nicht-blockierend).
  final Duration retryDelay;

  /// Maximale Anzahl Login-Versuche pro Refresh.
  static const int _maxRefreshAttempts = 2;

  final RestApiDOCUframeCallbacks? _callbacks;

  ApiRuntime? _runtime;

  /// Gespeichertes MD5-Passwort des letzten erfolgreichen Logins
  /// (Analogon zu `RestApiDOCUframeManager._password`); wird für den
  /// Session-Refresh benötigt.
  String _md5Password = '';

  /// Ein erfolgreicher Login oder explizit übergebene Credentials für eine
  /// wiederhergestellte Session erlauben den automatischen Refresh. Eine
  /// lediglich aus der Konfiguration übernommene Session-ID besitzt zunächst
  /// keine passenden Credentials.
  bool _automaticRefreshEnabled = false;

  /// Invalidiert bereits laufende Refreshes bei Logout oder einem neuen
  /// expliziten Login. So kann eine verspätete Login-Antwort keine bewusst
  /// beendete oder inzwischen ersetzte Session wiederherstellen.
  int _refreshGeneration = 0;

  /// Laufender Refresh (Single-Flight): parallele Aufrufer teilen sich
  /// dieses Future.
  Future<RefreshSessionResponse>? _ongoingRefresh;

  /// Recovery-lokaler 2FA-Zustand. Mehrere gleichzeitig fehlschlagende
  /// Requests dürfen weder mehrere Token-Dialoge noch unterschiedliche
  /// Login-Sequenzen starten.
  bool _recoveryNeedsTwoFactorToken = false;
  bool _recoveryTwoFactorTokenResolved = false;
  String _recoveryTwoFactorToken = '';
  Future<String>? _ongoingTwoFactorTokenRequest;

  SessionCoordinator({
    required this.configuration,
    SessionState? sessionState,
    RestApiDOCUframeCallbacks? callbacks,
    this.retryDelay = const Duration(milliseconds: 500),
  }) : sessionState =
           sessionState ?? SessionState(configuration.initialSessionId),
       _callbacks = callbacks {
    // Session-Änderungen an die App
    // weiterreichen; der Hook feuert nur bei tatsächlicher Wertänderung.
    this.sessionState.onSessionIdChanged = (sessionId) {
      _callbacks?.triggerSessionIdChangedEvent(sessionId);
    };
  }

  /// Ob aktuell eine Session vorliegt (nicht-leere Session-ID).
  bool get hasSession => sessionState.sessionId.isNotEmpty;

  /// Ob der Coordinator einen Session-Refresh sicher ausführen kann.
  bool get canRefreshSession =>
      _automaticRefreshEnabled && _md5Password.isNotEmpty;

  /// Hinterlegt das bereits gehashte Passwort für den nächsten automatischen
  /// Login bzw. für eine vorhandene Session. Damit erhält insbesondere eine
  /// über `configuration.sessionId` wiederhergestellte Session dieselbe
  /// Recovery-Fähigkeit wie nach einem Login. Ein leerer Wert entfernt die
  /// Credentials wieder.
  void setPassword(String md5Password) {
    _refreshGeneration++;
    _md5Password = md5Password;
    _automaticRefreshEnabled = md5Password.isNotEmpty;
  }

  /// Ersetzt den lokalen Sessionzustand kontrolliert, etwa beim Laden einer
  /// persistierten Session beim App-Start. Mit [md5Password] kann die
  /// automatische Session-Erneuerung direkt aktiviert werden.
  void restoreSession(String sessionId, {String md5Password = ''}) {
    _disableAutomaticRefresh();
    sessionState.sessionId = sessionId;
    if (sessionId.isNotEmpty && md5Password.isNotEmpty) {
      _md5Password = md5Password;
      _automaticRefreshEnabled = true;
    }
  }

  /// Verbindet den Koordinator mit dem [ApiRuntime], über den Login-,
  /// Logout- und Refresh-Requests laufen. Wird von der `ApiRuntime`-Factory
  /// aufgerufen; genau einmal.
  void attachRuntime(ApiRuntime runtime) {
    if (_runtime != null && !identical(_runtime, runtime)) {
      throw StateError(
        'SessionCoordinator ist bereits an einen anderen ApiRuntime '
        'gebunden.',
      );
    }
    _runtime = runtime;
  }

  ApiRuntime get _requireRuntime {
    final runtime = _runtime;
    if (runtime == null) {
      throw StateError(
        'SessionCoordinator ist nicht an einen ApiRuntime gebunden; '
        'den Koordinator über die ApiRuntime-Factory anbinden.',
      );
    }
    return runtime;
  }

  /// Meldet den Benutzer über `v2/login` an (Legacy-Vertrag).
  ///
  /// [md5Password] - Das bereits MD5-gehashte Passwort.
  /// [twoFactorAuthToken] - Optionales 2FA-Token; `null` lässt das Feld
  /// `2faToken` im Body weg (Legacy-Verhalten).
  ///
  /// Bei Erfolg wird das Passwort für spätere Refreshes gespeichert, die
  /// Session-ID in den [SessionState] übernommen und
  /// `onSessionIdChanged` ausgelöst. Bei JEDEM Fehler wird die Session
  /// geleert, `onSessionIdChanged('')` ausgelöst und die Exception
  /// weitergeworfen.
  Future<RestApiLoginResponse> login(
    String md5Password, {
    String? twoFactorAuthToken,
    bool refreshSession = false,
  }) async {
    // Ein neuer expliziter Login ersetzt vorherige Credentials. Schlägt er
    // fehl, darf ein späterer Request nicht unbemerkt den alten Benutzer
    // erneut anmelden.
    _disableAutomaticRefresh();
    try {
      return await _performLogin(
        md5Password,
        twoFactorAuthToken: twoFactorAuthToken,
        rememberCredentials: true,
        refreshGeneration: null,
      );
    } on Missing2FATokenException {
      if (!refreshSession) {
        rethrow;
      }

      final String token =
          await _callbacks?.triggerMissing2FATokenEvent() ?? '';
      if (token.isEmpty) {
        rethrow;
      }

      return _performLogin(
        md5Password,
        twoFactorAuthToken: token,
        rememberCredentials: true,
        refreshGeneration: null,
      );
    }
  }

  Future<RestApiLoginResponse> _performLogin(
    String md5Password, {
    required String? twoFactorAuthToken,
    required bool rememberCredentials,
    required int? refreshGeneration,
  }) async {
    final runtime = _requireRuntime;

    try {
      final RestApiLoginSecureKeyResponse keyResponse = await runtime.execute(
        ApiRequest<RestApiLoginSecureKeyResponse>(
          method: ApiHttpMethod.get,
          version: ApiVersion.v2,
          path: '/login/key',
          authentication: AuthenticationPolicy.none,
          responsePolicy: const _LoginSecureKeyResponsePolicy(),
          operationId: 'v2.login.key',
        ),
      );

      if (!keyResponse.isOk) {
        // Legacy-Parität: identische Fehlermeldung.
        throw Exception('Secure Key can not be provided');
      }

      _ensureRefreshIsCurrent(refreshGeneration);

      final String clearBody = jsonEncode(
        _buildLoginBody(md5Password, twoFactorAuthToken),
      );
      final String encryptedBody = await _buildEncryptedLoginBody(
        clearBody,
        keyResponse.key,
      );

      final RestApiLoginResponse loginResponse = await runtime.execute(
        ApiRequest<RestApiLoginResponse>(
          method: ApiHttpMethod.post,
          version: ApiVersion.v2,
          path: '/login',
          body: encryptedBody,
          authentication: AuthenticationPolicy.none,
          responsePolicy: const _LoginResponsePolicy(),
          operationId: 'v2.login',
        ),
      );

      _ensureRefreshIsCurrent(refreshGeneration);

      if (loginResponse.isOk) {
        if (rememberCredentials) {
          _md5Password = md5Password;
          _automaticRefreshEnabled = true;
        }
        sessionState.sessionId = loginResponse.sessionId;
      }

      return loginResponse;
    } catch (_) {
      if (refreshGeneration == null ||
          refreshGeneration == _refreshGeneration) {
        _clearSession();
      }
      rethrow;
    }
  }

  /// Meldet den Benutzer über `POST v1/logout` ab (Session-Header wird
  /// mitgesendet, aber ohne automatischen Session-Refresh).
  ///
  /// Die Session wird IMMER (`finally`) geleert und
  /// `onSessionIdChanged('')` ausgelöst - auch wenn der Server einen
  /// Fehler-Envelope liefert (die Exception wird weitergeworfen).
  Future<RestApiResponse> logout() async {
    final runtime = _requireRuntime;

    // Bereits vor dem HTTP-Aufruf deaktivieren, damit ein parallel
    // fehlschlagender Session-Request keinen Re-Login mehr starten kann.
    _disableAutomaticRefresh();

    try {
      return await runtime.execute(
        ApiRequest<RestApiResponse>(
          method: ApiHttpMethod.post,
          version: ApiVersion.v1,
          path: '/logout',
          authentication: AuthenticationPolicy.sessionNoRefresh,
          responsePolicy: const RestApiResponsePolicy(),
          operationId: 'v1.logout',
        ),
      );
    } finally {
      _clearSession();
    }
  }

  /// Erneuert die Session per Re-Login mit dem gespeicherten Passwort.
  ///
  /// Single-Flight: Parallele Aufrufer teilen sich das laufende Future,
  /// sodass nur EIN Key-Fetch-plus-Login-Vorgang stattfindet.
  ///
  /// Es werden bis zu zwei Versuche unternommen, mit nicht-blockierendem
  /// [retryDelay] dazwischen. Schlägt auch der letzte Versuch mit einer
  /// Exception fehl, wird sie weitergeworfen.
  Future<RefreshSessionResponse> refreshSession({
    String twoFaToken = '',
    bool requestTwoFactorToken = false,
  }) {
    if (!canRefreshSession) {
      return Future<RefreshSessionResponse>.value(
        RefreshSessionResponse(
          false,
          maxRetryCount: _maxRefreshAttempts,
          retryCount: 0,
          sessionId: '',
        ),
      );
    }

    if (requestTwoFactorToken) {
      _recoveryNeedsTwoFactorToken = true;
    }
    if (twoFaToken.isNotEmpty) {
      _recoveryNeedsTwoFactorToken = true;
      _recoveryTwoFactorTokenResolved = true;
      _recoveryTwoFactorToken = twoFaToken;
    }

    return _ongoingRefresh ??= _doRefreshSession().whenComplete(() {
      _ongoingRefresh = null;
      _resetTwoFactorRecovery();
    });
  }

  Future<RefreshSessionResponse> _doRefreshSession() async {
    // Zu Beginn einfrieren: Login-Fehler leeren zwar die Session, die beiden
    // Versuche dieses bereits autorisierten Refreshes dürfen aber weiterhin
    // dasselbe Credential verwenden.
    final String md5Password = _md5Password;
    final int refreshGeneration = _refreshGeneration;
    bool active = false;
    String newSessionId = '';
    int attempt = 0;

    // Gleichzeitig aus einem Multi-Demux fortgesetzte Futures erhalten eine
    // Microtask lang Gelegenheit, ihren 2FA-Bedarf an DIESELBE Recovery zu
    // melden, bevor der erste Login-Request gebaut wird.
    await Future<void>.delayed(Duration.zero);

    while (attempt < _maxRefreshAttempts && !active) {
      if (refreshGeneration != _refreshGeneration) {
        break;
      }
      String twoFactorAuthToken = '';
      if (_recoveryNeedsTwoFactorToken) {
        twoFactorAuthToken = await _resolveTwoFactorToken();
        if (twoFactorAuthToken.isEmpty) {
          break;
        }
      }

      attempt++;

      try {
        // Legacy-Parität: Der Refresh sendet `2faToken` immer mit
        // (ggf. als leeren String), der direkte Login nur bei Bedarf.
        final RestApiLoginResponse response = await _performLogin(
          md5Password,
          twoFactorAuthToken: twoFactorAuthToken,
          rememberCredentials: false,
          refreshGeneration: refreshGeneration,
        );

        if (response.isOk) {
          active = true;
          newSessionId = response.sessionId;
        }
      } on _RefreshCancelled {
        break;
      } on UserAndPassWrongException {
        // Terminale Auth-Fehler: Ein identischer zweiter Loginversuch mit
        // demselben Passwort/Token ändert das Ergebnis nicht und muss
        // unverfälscht propagieren. NICHT hierher gehören der generische
        // `WebServiceException`-Fallback (unbekannte/transiente Codes),
        // `SessionInvalidException`, `TokenOrSessionIsMissingException` und
        // `Missing2FATokenException` - diese sind potenziell transient und
        // durchlaufen daher den normalen Retry-Pfad unten.
        rethrow;
      } on LicenseException {
        rethrow;
      } on Require2FALoginException {
        rethrow;
      } on Invalid2FATokenException {
        rethrow;
      } on Missing2FATokenException {
        // Ein zunächst ohne Token gestarteter Refresh kann selbst 341
        // liefern. Der nächste Versuch holt das Token genau einmal über den
        // Recovery-weiten Callback. War bereits ein Token vorhanden, ist ein
        // identischer weiterer Versuch nicht sinnvoll.
        if (_recoveryTwoFactorTokenResolved) {
          rethrow;
        }
        _recoveryNeedsTwoFactorToken = true;
      } catch (_) {
        if (attempt >= _maxRefreshAttempts) {
          rethrow;
        }
      }

      if (!active && attempt < _maxRefreshAttempts) {
        // Nicht-blockierend warten (Legacy nutzte ein blockierendes
        // sleep()).
        await Future<void>.delayed(retryDelay);
      }
    }

    return RefreshSessionResponse(
      active,
      maxRetryCount: _maxRefreshAttempts,
      retryCount: attempt,
      sessionId: newSessionId,
    );
  }

  Future<String> _resolveTwoFactorToken() {
    if (_recoveryTwoFactorTokenResolved) {
      return Future<String>.value(_recoveryTwoFactorToken);
    }

    return _ongoingTwoFactorTokenRequest ??=
        () async {
          final String token =
              await _callbacks?.triggerMissing2FATokenEvent() ?? '';
          _recoveryTwoFactorToken = token;
          _recoveryTwoFactorTokenResolved = true;
          return token;
        }().whenComplete(() {
          _ongoingTwoFactorTokenRequest = null;
        });
  }

  void _resetTwoFactorRecovery() {
    _recoveryNeedsTwoFactorToken = false;
    _recoveryTwoFactorTokenResolved = false;
    _recoveryTwoFactorToken = '';
    _ongoingTwoFactorTokenRequest = null;
  }

  /// Baut den Klartext-Login-Body in exakt der Feldreihenfolge des
  /// Legacy-Managers: `user`, `pass`, optional `2faToken`, `appNames`,
  /// optional `device`, `furtherencryption`.
  Map<String, dynamic> _buildLoginBody(
    String md5Password,
    String? twoFactorAuthToken,
  ) {
    final Map<String, dynamic> body = {};

    body['user'] = configuration.userName;
    body['pass'] = md5Password;
    if (twoFactorAuthToken != null) {
      body['2faToken'] = twoFactorAuthToken;
    }
    body['appNames'] = configuration.getAllAppNames();
    final RestApiDevice? device = configuration.device;
    if (device != null) {
      body['device'] = device.toJson();
    }
    body['furtherencryption'] = false;

    return body;
  }

  /// Verschlüsselt den Klartext-Body exakt wie
  /// `RestApiDOCUframeManager._getv2LoginBody`:
  /// AES-verschlüsselter Body (IV(16) + Ciphertext, Base64),
  /// RSA-verschlüsselter AES-Schlüssel und eigener Public Key (PEM).
  Future<String> _buildEncryptedLoginBody(
    String clearBody,
    String serverPublicKeyPem,
  ) async {
    final publicKey = serverPublicKeyPem.parsePublicKeyFromPem();

    await EncryptionManager().initializeRSAKeyPair();
    await EncryptionManager().initializeAESKey();

    final Map<String, dynamic> encryptedBodyJson =
        jsonDecode(
              await EncryptionManager().encryptAES(clearBody, padding: 'PKCS7'),
            )
            as Map<String, dynamic>;

    final Uint8List encryptedBodyIv = base64Decode(
      encryptedBodyJson['iv'] ?? '',
    );
    final Uint8List encryptedBodyData = base64Decode(
      encryptedBodyJson['data'] ?? '',
    );

    final Uint8List encryptedBodyMerged = Uint8List(
      encryptedBodyIv.length + encryptedBodyData.length,
    );
    encryptedBodyMerged.setRange(0, encryptedBodyIv.length, encryptedBodyIv);
    encryptedBodyMerged.setRange(
      encryptedBodyIv.length,
      encryptedBodyMerged.length,
      encryptedBodyData,
    );

    final String encryptedBodyBase64 = base64.encode(encryptedBodyMerged);

    final String encryptedAesKeyBase64 = base64.encode(
      await EncryptionManager().encryptRSA(
        EncryptionManager().keyAES!.bytes,
        publicKey: publicKey,
      ),
    );

    final String publicKeyBase64 = EncryptionManager().keyRSA!.publicKey
        .encodeToPem();

    return jsonEncode({
      'aesKey': encryptedAesKeyBase64,
      'data': encryptedBodyBase64,
      'publicKey': publicKeyBase64,
    });
  }

  /// Leert die Session und garantiert genau EIN
  /// `onSessionIdChanged('')`-Event - auch wenn die Session-ID bereits
  /// leer war (der Hook im [SessionState] feuert nur bei Wertänderung,
  /// der Legacy-Manager triggert das Event dagegen immer).
  void _clearSession() {
    if (sessionState.sessionId.isEmpty) {
      _callbacks?.triggerSessionIdChangedEvent('');
    } else {
      sessionState.sessionId = '';
    }
  }

  void _disableAutomaticRefresh() {
    _refreshGeneration++;
    _automaticRefreshEnabled = false;
    _md5Password = '';
  }

  void _ensureRefreshIsCurrent(int? refreshGeneration) {
    if (refreshGeneration != null && refreshGeneration != _refreshGeneration) {
      throw const _RefreshCancelled();
    }
  }
}

class _RefreshCancelled implements Exception {
  const _RefreshCancelled();
}

/// Dekodiert `GET v2/login/key` über das bestehende
/// [RestApiLoginSecureKeyResponse].
class _LoginSecureKeyResponsePolicy
    implements ResponsePolicy<RestApiLoginSecureKeyResponse> {
  const _LoginSecureKeyResponsePolicy();

  @override
  RestApiLoginSecureKeyResponse decode(TransportResponse response) =>
      RestApiLoginSecureKeyResponse(_toHttpResponse(response));
}

/// Dekodiert `POST v2/login` über das bestehende [RestApiLoginResponse].
class _LoginResponsePolicy implements ResponsePolicy<RestApiLoginResponse> {
  const _LoginResponsePolicy();

  @override
  RestApiLoginResponse decode(TransportResponse response) =>
      RestApiLoginResponse(_toHttpResponse(response));
}

http.Response _toHttpResponse(TransportResponse response) =>
    http.Response.bytes(
      response.bodyBytes,
      response.statusCode,
      headers: response.headers,
    );
