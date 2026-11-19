import 'dart:convert';

import 'package:gsd_restapi/src/crypto/handshake_crypto.dart';
import 'package:gsd_restapi/src/exceptions/gsd_api_exception.dart';
import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/gsd_login_result.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/model_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:gsd_restapi/src/runtime/response/response_envelope.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:gsd_restapi/src/runtime/runtime_events.dart';
import 'package:gsd_restapi/src/runtime/session/login_secure_key_result.dart';
import 'package:gsd_restapi/src/runtime/session/session_state.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:meta/meta.dart';

/// Koordiniert Login, Logout und Session-Refresh gegen die DOCUframe-API
/// über den neuen Runtime (nicht über den Legacy-Manager).
///
/// Der Login reproduziert den Legacy-Vertrag von
/// `login()`/`_getv2LoginBody()` des Legacy-Managers (bis 0.2.x) exakt:
///
/// 1. `GET v2/login/key` (ohne Session-Header, nie gepuffert) liefert den
///    öffentlichen RSA-Schlüssel des Servers (`data.key`).
/// 2. Der Klartext-Body
///    `{user, pass, [2faToken], appNames, [device], furtherencryption: false}`
///    wird AES-verschlüsselt (IV(16) +
///    Ciphertext, Base64), der AES-Schlüssel RSA-verschlüsselt und
///    zusammen mit dem eigenen Public Key als
///    `{aesKey, data, publicKey}` an `POST v2/login` gesendet
///    ([HandshakeCrypto.encryptLoginBody]; der AES-Schlüssel entsteht je
///    Login und liegt nur im Speicher).
/// 3. `data` der Antwort wird ein [GsdLoginResult]; die Session-ID wandert
///    in den [SessionState].
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
  SessionCoordinator({
    required this.configuration,
    SessionState? sessionState,
    RuntimeEvents? events,
    this.retryDelay = const Duration(milliseconds: 500),
  }) : sessionState =
           sessionState ?? SessionState(configuration.initialSessionId),
       _events = events {
    // Session-Änderungen an die App
    // weiterreichen; der Hook feuert nur bei tatsächlicher Wertänderung.
    this.sessionState.onSessionIdChanged = (sessionId) {
      _events?.sessionIdChanged(sessionId);
    };
  }

  /// Runtime-Konfiguration (Benutzer, App-Namen, Gerät).
  final RuntimeConfiguration configuration;

  /// Gemeinsamer Session-Zustand; wird auch vom `HeaderProvider` des
  /// angebundenen [ApiRuntime] gelesen.
  final SessionState sessionState;

  /// Wartezeit zwischen zwei Refresh-Versuchen (nicht-blockierend).
  final Duration retryDelay;

  /// Maximale Anzahl Login-Versuche pro Refresh.
  static const int _maxRefreshAttempts = 2;

  final RuntimeEvents? _events;

  ApiRuntime? _runtime;

  /// Gespeichertes MD5-Passwort des letzten erfolgreichen Logins
  /// (Analogon zu `_password` des Legacy-Managers); wird für den
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
  Future<bool>? _ongoingRefresh;

  /// Recovery-lokaler 2FA-Zustand. Mehrere gleichzeitig fehlschlagende
  /// Requests dürfen weder mehrere Token-Dialoge noch unterschiedliche
  /// Login-Sequenzen starten.
  bool _recoveryNeedsTwoFactorToken = false;
  bool _recoveryTwoFactorTokenResolved = false;
  String _recoveryTwoFactorToken = '';
  Future<String>? _ongoingTwoFactorTokenRequest;

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
  /// Session-ID in den [SessionState] übernommen und an
  /// [RuntimeEvents.sessionIdChanges] gemeldet. Bei JEDEM Fehler wird die
  /// Session geleert, `''` gemeldet und die Exception weitergeworfen.
  ///
  /// Ein 341 wirft [GsdTwoFactorTokenMissingException] an den Aufrufer; den
  /// 2FA-Token-Provider fragt nur der Refresh einer laufenden Sitzung.
  Future<GsdLoginResult> login(
    String md5Password, {
    String? twoFactorAuthToken,
  }) {
    // Ein neuer expliziter Login ersetzt vorherige Credentials. Schlägt er
    // fehl, darf ein späterer Request nicht unbemerkt den alten Benutzer
    // erneut anmelden.
    _disableAutomaticRefresh();
    return _performLogin(
      md5Password,
      twoFactorAuthToken: twoFactorAuthToken,
      rememberCredentials: true,
      refreshGeneration: null,
    );
  }

  Future<GsdLoginResult> _performLogin(
    String md5Password, {
    required String? twoFactorAuthToken,
    required bool rememberCredentials,
    required int? refreshGeneration,
  }) async {
    final runtime = _requireRuntime;

    try {
      final keyResponse = await runtime.execute(
        const ApiRequest<LoginSecureKeyResult>(
          method: GsdHttpMethod.get,
          version: GsdApiVersion.v2,
          path: '/login/key',
          authentication: AuthenticationPolicy.none,
          responsePolicy: _LoginSecureKeyResponsePolicy(),
          operationId: 'v2.login.key',
        ),
      );

      _ensureRefreshIsCurrent(refreshGeneration);

      final clearBody = jsonEncode(
        _buildLoginBody(md5Password, twoFactorAuthToken),
      );
      final encryptedBody = await HandshakeCrypto.encryptLoginBody(
        clearBody,
        serverPublicKeyPem: keyResponse.key,
      );

      final loginResult = await runtime.execute(
        ApiRequest<GsdLoginResult>(
          method: GsdHttpMethod.post,
          version: GsdApiVersion.v2,
          path: '/login',
          body: encryptedBody,
          authentication: AuthenticationPolicy.none,
          responsePolicy: const ModelResponsePolicy<GsdLoginResult>(
            GsdLoginResult.fromJson,
          ),
          operationId: 'v2.login',
        ),
      );

      _ensureRefreshIsCurrent(refreshGeneration);

      if (rememberCredentials) {
        _md5Password = md5Password;
        _automaticRefreshEnabled = true;
      }
      sessionState.sessionId = loginResult.sessionId;

      return loginResult;
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
  /// Die Session wird IMMER (`finally`) geleert und `''` gemeldet - auch
  /// wenn der Server einen Fehler-Envelope liefert (die Exception wird
  /// weitergeworfen).
  Future<Object?> logout() async {
    final runtime = _requireRuntime;

    // Bereits vor dem HTTP-Aufruf deaktivieren, damit ein parallel
    // fehlschlagender Session-Request keinen Re-Login mehr starten kann.
    _disableAutomaticRefresh();

    try {
      return await runtime.execute(
        const ApiRequest<Object?>(
          method: GsdHttpMethod.post,
          version: GsdApiVersion.v1,
          path: '/logout',
          authentication: AuthenticationPolicy.sessionNoRefresh,
          responsePolicy: DataResponsePolicy<Object?>(),
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
  ///
  /// Liefert, ob die Session erneuert wurde; `false` ohne gespeichertes
  /// Passwort, ohne 2FA-Token oder nach Logout/`dispose()` währenddessen.
  Future<bool> refreshSession({
    String twoFaToken = '',
    bool requestTwoFactorToken = false,
  }) {
    if (!canRefreshSession) {
      return Future<bool>.value(false);
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

  Future<bool> _doRefreshSession() async {
    // Zu Beginn einfrieren: Login-Fehler leeren zwar die Session, die beiden
    // Versuche dieses bereits autorisierten Refreshes dürfen aber weiterhin
    // dasselbe Credential verwenden.
    final md5Password = _md5Password;
    final refreshGeneration = _refreshGeneration;
    var active = false;
    var attempt = 0;

    // Gleichzeitig aus einem Multi-Demux fortgesetzte Futures erhalten eine
    // Microtask lang Gelegenheit, ihren 2FA-Bedarf an DIESELBE Recovery zu
    // melden, bevor der erste Login-Request gebaut wird.
    await Future<void>.delayed(Duration.zero);

    while (attempt < _maxRefreshAttempts && !active) {
      if (refreshGeneration != _refreshGeneration) {
        break;
      }
      var twoFactorAuthToken = '';
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
        await _performLogin(
          md5Password,
          twoFactorAuthToken: twoFactorAuthToken,
          rememberCredentials: false,
          refreshGeneration: refreshGeneration,
        );

        active = true;
      } on _RefreshCancelled {
        break;
      } on GsdInvalidCredentialsException {
        // Terminale Auth-Fehler: Ein identischer zweiter Loginversuch mit
        // demselben Passwort/Token ändert das Ergebnis nicht und muss
        // unverfälscht propagieren. NICHT hierher gehören der generische
        // `GsdServerException`-Fallback (unbekannte/transiente Codes),
        // `GsdSessionInvalidException`, `GsdSessionMissingException` und
        // `GsdTwoFactorTokenMissingException` - diese sind potenziell
        // transient und durchlaufen daher den normalen Retry-Pfad unten.
        rethrow;
      } on GsdLicenseException {
        rethrow;
      } on GsdTwoFactorRequiredException {
        rethrow;
      } on GsdTwoFactorTokenInvalidException {
        rethrow;
      } on GsdTwoFactorTokenMissingException {
        // Ein zunächst ohne Token gestarteter Refresh kann selbst 341
        // liefern. Der nächste Versuch holt das Token genau einmal über den
        // Recovery-weiten Provider. War bereits ein Token vorhanden, ist ein
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

    return active;
  }

  Future<String> _resolveTwoFactorToken() {
    if (_recoveryTwoFactorTokenResolved) {
      return Future<String>.value(_recoveryTwoFactorToken);
    }

    return _ongoingTwoFactorTokenRequest ??=
        () async {
          final token = await _events?.requestTwoFactorToken() ?? '';
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
    final body = <String, dynamic>{};

    body['user'] = configuration.userName;
    body['pass'] = md5Password;
    if (twoFactorAuthToken != null) {
      body['2faToken'] = twoFactorAuthToken;
    }
    body['appNames'] = configuration.getAllAppNames();
    final device = configuration.device;
    if (device != null) {
      body['device'] = device.toJson();
    }
    body['furtherencryption'] = false;

    return body;
  }

  /// Leert die Session und meldet genau EIN `''` - auch wenn die
  /// Session-ID bereits leer war (der Hook im [SessionState] feuert nur bei
  /// Wertänderung, der Legacy-Manager meldete dagegen immer).
  void _clearSession() {
    if (sessionState.sessionId.isEmpty) {
      _events?.sessionIdChanged('');
    } else {
      sessionState.sessionId = '';
    }
  }

  /// Bricht einen laufenden Refresh ab und schließt offene 2FA-Anfragen mit
  /// `''` ab. Danach startet kein automatischer Refresh mehr. Die Session-ID
  /// bleibt stehen; ein Server-Logout findet nicht statt.
  void dispose() {
    _disableAutomaticRefresh();
    _events?.cancelTwoFactorRequests();
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

/// Dekodiert `GET v2/login/key`: Umschlag, dann `data.key`.
class _LoginSecureKeyResponsePolicy
    implements IResponsePolicy<LoginSecureKeyResult> {
  const _LoginSecureKeyResponsePolicy();

  @override
  LoginSecureKeyResult decode(
    TransportResponse response, {
    required String operationId,
  }) => LoginSecureKeyResult.fromEnvelope(
    ResponseEnvelope.decode(response, operationId: operationId),
    operationId: operationId,
  );
}
