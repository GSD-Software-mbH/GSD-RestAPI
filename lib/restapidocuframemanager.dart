part of 'gsd_restapi.dart';

/// Enum für unterstützte HTTP-Methoden
///
/// Definiert alle HTTP-Methoden, die von der REST-API unterstützt werden.
enum HttpMethod {
  /// GET-Anfrage zum Abrufen von Daten
  get,

  /// POST-Anfrage zum Erstellen neuer Ressourcen
  post,

  /// PUT-Anfrage zum vollständigen Ersetzen einer Ressource
  put,

  /// PATCH-Anfrage zum teilweisen Aktualisieren einer Ressource
  patch,

  /// DELETE-Anfrage zum Löschen einer Ressource
  delete,
}

/// Enum für Request-Prioritäten
///
/// Definiert die verschiedenen Prioritätsstufen für API-Requests.
/// Beeinflusst die Verarbeitung und das Buffering von Multi-Requests.
enum RequestPriority {
  /// Niedrige Priorität - Hintergrund-Operationen, längeres Buffering
  low,

  /// Normale Priorität - Standard-Requests, normales Buffering
  normal,

  /// Hohe Priorität - Sofortige Verarbeitung, kein Buffering
  high,
}

/// Hauptklasse für alle REST-API-bezogenen Daten und Funktionen
///
/// Diese Klasse verwaltet die Kommunikation mit der REST-API, einschließlich
/// Authentifizierung, Session-Management, HTTP-Anfragen und Antwortverarbeitung.
///
/// **NEUE MODULARE ARCHITEKTUR:**
/// Diese Klasse wurde refaktoriert, um eine modulare Architektur zu verwenden:
/// - `config`: Zentrale Konfigurationsverwaltung (RestApiConfig)
/// - `callbacks`: Event-System und Callback-Management (RestApiCallbacks)
///
/// Hauptfunktionen:
/// - Benutzeranmeldung und Session-Verwaltung
/// - HTTP-Anfragen mit automatischer Session-Erneuerung
/// - Verschlüsselung und Entschlüsselung von Anfragen/Antworten
/// - Firebase Performance-Monitoring
/// - Fehlerbehandlung und Exception-Management
class RestApiDOCUframeManager {
  /// Getter für ausstehende HTTP-Anfragen
  Map<String, RestApiRequest> get pendingResponses => _pendingResponses;

  /// Getter für den Anmeldestatus
  bool get loggedIn => _loggedIn;

  /// Getter für die Konfiguration
  RestApiDOCUframeConfig get config => _config;

  /// Callback-System für Event-Management
  late RestApiDOCUframeCallbacks callbacks;

  /// Passwort als MD5-Hash
  ///
  /// Beispiel: `098f6bcd4621d373cade4e832627b4f6` für das Passwort `test`.
  /// Das Passwort wird immer als MD5-Hash gespeichert und übertragen.
  String _password = "";

  /// Basis-URI für alle API-Aufrufe
  ///
  /// Wird aus der Server-URL generiert und für die Konstruktion von Request-URIs verwendet.
  Uri _baseUri = Uri();

  /// Aktuelle Session-ID vom Login-Vorgang
  ///
  /// Wird bei erfolgreicher Anmeldung vom Server zurückgegeben und für
  /// alle nachfolgenden API-Aufrufe verwendet.

  /// Map der aktuell laufenden HTTP-Anfragen
  ///
  /// Verhindert doppelte Anfragen und ermöglicht das Tracking von parallelen Requests.
  final Map<String, RestApiRequest> _pendingResponses = {};

  /// Anmeldestatus des Benutzers
  bool _loggedIn = false;

  /// Buffer für Multi-Request-Verarbeitung (Legacy - wird durch Priority-Buffer ersetzt)
  final List<RestAPIBufferedRequest> _requestBuffer = [];

  /// Priority-basierte Buffer für Multi-Request-Verarbeitung
  final Map<RequestPriority, List<RestAPIBufferedRequest>> _priorityBuffers = {
    RequestPriority.high: [],
    RequestPriority.normal: [],
    RequestPriority.low: [],
  };

  /// Zone-lokaler Schlüssel für das Überspringen des Buffering
  ///
  /// Wird verwendet, um Zone-spezifisch zu markieren, dass Requests
  /// nicht gepuffert werden sollen. Dies beeinflusst nur den aktuellen
  /// Execution-Context, nicht andere gleichzeitige Requests.
  static const String _skipBufferingZoneKey = 'skipBuffering';

  /// Zone-lokaler Schlüssel für Request-Priorität
  ///
  /// Wird verwendet, um die Priorität von Requests im Zone-Kontext zu setzen.
  /// Ermöglicht priority-basierte Verarbeitung und Buffering.
  static const String _priorityZoneKey = 'requestPriority';

  /// Überprüft, ob der aktuelle Request im "skip buffering" Kontext läuft
  ///
  /// Prüft die Zone-lokale Variable, um zu bestimmen, ob Requests
  /// in der aktuellen Zone vom MultiRequest-Buffering ausgeschlossen werden sollen.
  bool get _isInSkipBufferingContext {
    return Zone.current[_skipBufferingZoneKey] == true;
  }

  /// Ermittelt die aktuelle Request-Priorität aus dem Zone-Kontext
  ///
  /// Prüft die Zone-lokale Variable für die Priorität.
  /// Gibt RequestPriority.normal zurück, falls keine Priorität gesetzt ist.
  RequestPriority get _currentZonePriority {
    return Zone.current[_priorityZoneKey] ?? RequestPriority.normal;
  }

  /// Timer für automatisches Buffer-Flushing
  Timer? _bufferFlushTimer;

  /// Priority-spezifische Timer für automatisches Buffer-Flushing
  final Map<RequestPriority, Timer?> _priorityFlushTimers = {
    RequestPriority.high: null,
    RequestPriority.normal: null,
    RequestPriority.low: null,
  };

  /// Priority-spezifische Multi-Request-Verarbeitung
  final Map<RequestPriority, bool> _isProcessingPriorityMultiRequest = {
    RequestPriority.high: false,
    RequestPriority.normal: false,
    RequestPriority.low: false,
  };

  /// Kennzeichnet manuelle Abmeldung
  ///
  /// Verhindert automatische Session-Erneuerung nach manueller Abmeldung.
  bool _manualLoggedOut = false;

  /// Map für aktive Upload-Controller
  final Map<String, RestAPIFileUploadController> _activeUploads = {};

  /// Future für laufende Login-Operationen zur Synchronisation
  /// Verhindert mehrere parallele Login-Requests
  Future<RefreshSessionResponse>? _ongoingLogin;

  // Plattformabhängige Auswahl des richtigen HTTP-Clients:
  late http.Client _client;

  /// Konfigurationsmodul für alle API-Parameter
  final RestApiDOCUframeConfig _config;

  /// Prüft, ob ein Request-Type nie gepuffert werden soll
  ///
  /// Diese Methode bestimmt, welche Request-Typen immer als Einzelanfragen
  /// gesendet werden sollen und nie in den Multi-Request-Buffer gelangen.
  ///
  /// Ausgeschlossene Request-Typen:
  /// - Login-Requests (v2/login, v2/login/secure)
  /// - Logout-Requests (v1/logout)
  /// - Session-Checks (_CheckSession)
  /// - Service-Checks (_CheckService)
  ///
  /// [function] - Der Function-Name des Requests
  /// [login] - Kennzeichnet Login-Requests
  ///
  /// Returns: true wenn Request nie gepuffert werden soll, false sonst
  bool _shouldNeverBuffer(String function) {
    // Bestimmte Funktionen nie puffern
    final neverBufferFunctions = {
      'v1/logout',
      'v2/login/secure/key',
      'v2/login/key',
      'v2/login',
      '_CheckSession',
      '_CheckService',
      '/v1/xSync',
    };

    return neverBufferFunctions.contains(function);
  }

  /// Erstellt eine neue RestApiDOCUframeManager-Instanz
  ///
  /// Initialisiert den Manager mit der erforderlichen Konfiguration und
  /// optionalen Callback-Funktionen für Event-Handling.
  ///
  /// [config] - Konfigurationsobjekt mit allen erforderlichen Verbindungsparametern
  /// [callbacks] - Optionales Callback-System für Event-Management
  ///
  /// Die Konfiguration enthält:
  /// - App-Schlüssel für die API-Authentifizierung
  /// - Benutzername für die Anmeldung
  /// - Liste der Anwendungsnamen
  /// - Server-URL mit Protokoll, IP und Port
  /// - Datenbank-Alias
  /// - Geräteinformationen (optional)
  /// - Paginierungs- und Buffer-Einstellungen
  /// - SSL- und Multi-Request-Konfiguration
  RestApiDOCUframeManager({
    required RestApiDOCUframeConfig config,
    RestApiDOCUframeCallbacks? callbacks,
  }) : _config = config {
    _baseUri = Uri.parse(_config.serverUrl);

    this.callbacks = callbacks ?? RestApiDOCUframeCallbacks();

    _client = createClient(
      _config.connectionTimeout,
      allowSslError: _config.allowSslError,
    );
  }

  /// Setzt das Passwort für die Authentifizierung
  ///
  /// [password] - Das Passwort (wird intern als MD5-Hash gespeichert)
  void setPassword(String password) {
    _password = password;
  }

  /// Erstellt HTTP-Header für API-Anfragen (delegiert an config)
  ///
  /// [contentType] - MIME-Type des Request-Bodies (Standard: "application/json")
  /// [addAppKey] - App-Schlüssel zu Headern hinzufügen (Standard: true)
  /// [addSessionId] - Session-ID zu Headern hinzufügen (Standard: true)
  ///
  /// Returns: Map mit allen erforderlichen HTTP-Headern
  Map<String, String> _getHeader({
    String contentType = "application/json; charset=utf-8",
    bool addAppKey = true,
    bool addSessionId = true,
  }) {
    return _config.getHeaders(
      contentType: contentType,
      addAppKey: addAppKey,
      addSessionId: addSessionId,
    );
  }

  /// Erstellt eine vollständige URI für API-Aufrufe
  ///
  /// Kombiniert die Basis-URI mit dem angegebenen Pfad und optionalen
  /// Query-Parametern zu einer vollständigen Request-URI.
  ///
  /// [path] - Der API-Endpunkt-Pfad (z.B. "/v1/objects/Vorgang")
  /// [params] - Optionale Query-Parameter als Map
  ///
  /// Returns: [Uri] - Die vollständige URI für den API-Aufruf
  ///
  /// Beispiel:
  /// ```dart
  /// Uri requestUri = _getUri(
  ///   "/v1/folders/type/Eingang",
  ///   params: {"page": "1", "perPage": "50"}
  /// );
  /// // Ergebnis: https://server.com:8080/dfapp/v1/folders/type/Eingang?page=1&perPage=50
  /// ```
  Uri _getUri(String path, {Map<String, String>? params}) {
    String pathCombined;

    if (_config.useBase64UrlParameter && params != null && params.isNotEmpty) {
      String encodedParams = base64Url.encode(
        utf8.encode(
          params.entries
              .map((e) => "${e.key}=${Uri.encodeComponent(e.value)}")
              .join("&"),
        ),
      );
      params = {"qb64": encodedParams};
    }

    pathCombined = "${_baseUri.path}$path";
    Uri uri = _baseUri.replace(path: pathCombined, queryParameters: params);

    return uri;
  }

  Future<http.Response> _http(
    HttpMethod method,
    Uri requestUri,
    String function, {
    String? body,
    Map<String, String>? requestHeader,
    bool handleSession = true,
    bool useRequestHeader = true,
    bool login = false,
    bool multiRetry = false,
    bool refreshSession = false,
  }) async {
    http.Response httpResponse;
    bool repeat = false;

    do {
      if (useRequestHeader) {
        requestHeader ??= _getHeader();
      }

      callbacks.triggerLogEvent("RequestUri send: $requestUri");
      callbacks.triggerLogEvent("Request Header: $requestHeader");
      callbacks.triggerLogEvent(
        "Request Body: ${(body?.length ?? 0) > 1000 ? "${body?.substring(0, 1000)}..." : body}",
      );

      if (kDebugMode) {
        debugPrint("RequestUri send: $requestUri");
        debugPrint("Request Header: $requestHeader");
        debugPrint(
          "Request Body: ${(body?.length ?? 0) > 1000 ? "${body?.substring(0, 1000)}..." : body}",
        ); // dont trace full email content = performance issue
      }

      httpResponse = await _performRequest(
        requestUri: requestUri,
        requestHeader: requestHeader,
        body: body,
        method: method,
        connectionTimeout: _config.connectionTimeout,
        responseTimeout: _config.responseTimeout,
        function: function,
        multiRetry: multiRetry,
        login: login,
      );

      if (!httpResponse.body.isValidJson()) {
        String decodedResponseBody = "";

        List<String> responseBodyParts = httpResponse.body.split("|");

        String aesKeyPart = responseBodyParts[0];
        String bodyPart = responseBodyParts[1];

        String aesKeyString = base64Encode(
          await EncryptionManager().decryptRSA(base64Decode(aesKeyPart)),
        );

        encrpyt.Key aesKey = encrpyt.Key.fromBase64(aesKeyString);

        Uint8List bodyPartBytes = base64Decode(bodyPart);

        Map<String, dynamic> aesJson = {
          "iv": base64Encode(bodyPartBytes.sublist(0, 16)),
          "data": base64Encode(bodyPartBytes.sublist(16, bodyPartBytes.length)),
        };

        decodedResponseBody = await EncryptionManager().decryptAES(
          jsonEncode(aesJson),
          key: aesKey,
          padding: "PKCS7",
        );

        httpResponse = http.Response(
          decodedResponseBody,
          httpResponse.statusCode,
          headers: httpResponse.headers,
        );
      }

      if (useRequestHeader && requestHeader != null) {
        try {
          RestApiResponse(httpResponse);
          repeat = false;
        } on SessionInvalidException {
          if (handleSession && _loggedIn && !_manualLoggedOut) {
            RefreshSessionResponse response =
                await _synchronizedRefreshSession();
            if (response.isActive) {
              repeat = true;
              requestHeader['sessionid'] = response.sessionId;
            }
          }
        } on TokenOrSessionIsMissingException {
          if (handleSession && _loggedIn && !_manualLoggedOut) {
            RefreshSessionResponse response =
                await _synchronizedRefreshSession();
            if (response.isActive) {
              repeat = true;
              requestHeader['sessionid'] = response.sessionId;
            }
          }
        } on UserAndPassWrongException catch (e) {
          callbacks.triggerUserAndPassWrongEvent(e);
          rethrow;
        } on LicenseException catch (e) {
          callbacks.triggerLicenseWrongEvent(e);
          rethrow;
        } on Missing2FATokenException {
          if (!refreshSession) {
            rethrow;
          }

          String newToken = await callbacks.triggerMissing2FATokenEvent();

          if (newToken.isEmpty) {
            rethrow;
          }

          RefreshSessionResponse response = await _synchronizedRefreshSession(
            twoFaToken: newToken,
          );

          if (response.isActive) {
            repeat = true;
            requestHeader['sessionid'] = response.sessionId;
          }
        } catch (e) {
          rethrow;
        }
      }
    } while (repeat);

    _loggedIn = true;

    return (httpResponse);
  }

  Future<http.Response> _performRequest({
    required Uri requestUri,
    required Map<String, String>? requestHeader,
    required dynamic body,
    required HttpMethod method,
    required Duration connectionTimeout,
    required Duration responseTimeout,
    required String function,
    bool multiRetry = false,
    bool login = false,
  }) async {
    RestApiRequest request = RestApiRequest(
      requestUri,
      requestHeader,
      body,
      method,
      connectionTimeout,
      responseTimeout,
      function,
      login: login,
    );

    final String requestHash = request.requestHash;

    if (_pendingResponses.containsKey(requestHash) && !multiRetry) {
      return await _pendingResponses[requestHash]!.execute(_client);
    }

    if (login) {
      RestApiRequest? request = _pendingResponses.values.firstWhereOrNull(
        (element) => element.login,
      );

      if (request != null) {
        return await request.execute(_client);
      }
    }

    // Multi-Request-Verarbeitung für normale Requests
    // Bestimmte Request-Typen werden nie gepuffert oder sind explizit ausgeschlossen
    if (_config.multiRequest &&
        !_shouldNeverBuffer(function) &&
        !_isInSkipBufferingContext &&
        !multiRetry) {
      return await _performPriorityBufferedRequest(
        requestUri,
        requestHeader,
        body,
        method,
        function,
      );
    }

    // Normale Einzelanfrage-Verarbeitung
    _pendingResponses[requestHash] = request;

    try {
      http.Response response = await request.execute(_client);

      return response;
    } finally {
      callbacks.triggerHttpMetricRecordedEvent(request.metric!);
      _pendingResponses.remove(requestHash);
    }
  }

  /// Verarbeitet eine gepufferte Anfrage mit Priority-System
  Future<http.Response> _performPriorityBufferedRequest(
    Uri requestUri,
    Map<String, String>? requestHeader,
    dynamic body,
    HttpMethod method,
    String function,
  ) async {
    final priority = _currentZonePriority;
    final completer = Completer<http.Response>();

    final bufferedRequest = RestAPIBufferedRequest(
      requestUri: requestUri,
      requestHeader: requestHeader,
      body: body,
      method: method,
      function: function,
      completer: completer,
    );

    // Request zum entsprechenden Priority-Buffer hinzufügen
    _priorityBuffers[priority]!.add(bufferedRequest);

    // Auch Legacy-Buffer für Backward-Compatibility befüllen
    _requestBuffer.add(bufferedRequest);

    // Priority-basierte Buffer-Flush-Logik
    _resetPriorityBufferFlushTimer(priority);

    if (_priorityBuffers[priority]!.length >= _config.maxBufferSize) {
      _flushPriorityRequestBuffer(priority);
    }

    return completer.future;
  }

  /// Setzt den Priority-spezifischen Buffer-Flush-Timer zurück
  void _resetPriorityBufferFlushTimer(RequestPriority priority) {
    _priorityFlushTimers[priority]?.cancel();

    if (_priorityBuffers[priority]!.isNotEmpty) {
      _priorityFlushTimers[priority] = Timer(
        Duration(milliseconds: _config.bufferFlushDelayMs),
        () => _flushPriorityRequestBuffer(priority),
      );
    }
  }

  /// Leert den Priority-spezifischen Request-Buffer
  void _flushPriorityRequestBuffer(RequestPriority priority) {
    final buffer = _priorityBuffers[priority]!;
    if (buffer.isEmpty || _isProcessingPriorityMultiRequest[priority] == true) {
      return;
    }

    _priorityFlushTimers[priority]?.cancel();
    _isProcessingPriorityMultiRequest[priority] = true;

    // Kopie des Priority-Buffers erstellen und originalen Buffer leeren
    List<RestAPIBufferedRequest> requestsToProcess = List.from(buffer);
    buffer.clear();

    // Aus Legacy-Buffer entfernen
    for (final request in requestsToProcess) {
      _requestBuffer.remove(request);
    }

    // Prüfen ob nur ein Request vorhanden ist oder High-Priority
    if (requestsToProcess.length == 1 || priority == RequestPriority.high) {
      // Einzelanfrage direkt verarbeiten
      _retryAsSingleRequest(requestsToProcess.first)
          .then((_) {
            _isProcessingPriorityMultiRequest[priority] = false;

            // Falls während der Verarbeitung neue Requests hinzugekommen sind
            if (buffer.isNotEmpty) {
              _resetPriorityBufferFlushTimer(priority);
            }
          })
          .catchError((error) {
            _isProcessingPriorityMultiRequest[priority] = false;

            // Fehlerbehandlung für Einzelanfrage
            if (!requestsToProcess.first.completer.isCompleted) {
              requestsToProcess.first.completer.completeError(error);
            }
          });
    } else {
      // Multi-Request asynchron verarbeiten für mehrere Requests
      _processPriorityMultiRequest(requestsToProcess, priority)
          .then((_) {
            _isProcessingPriorityMultiRequest[priority] = false;

            // Falls während der Verarbeitung neue Requests hinzugekommen sind
            if (buffer.isNotEmpty) {
              _resetPriorityBufferFlushTimer(priority);
            }
          })
          .catchError((error) {
            _isProcessingPriorityMultiRequest[priority] = false;

            // Fehlerbehandlung: Alle wartenden Requests mit Fallback abschließen
            _fallbackToIndividualRequests(requestsToProcess);
          });
    }
  }

  /// Verarbeitet mehrere Anfragen als Priority-basierter Multi-Request
  Future<void> _processPriorityMultiRequest(
    List<RestAPIBufferedRequest> requests,
    RequestPriority priority,
  ) async {
    if (requests.isEmpty) return;

    try {
      // Multi-Request-Body erstellen
      List<Map<String, dynamic>> requestsList = requests
          .map((req) => req.toMultiRequestJson())
          .toList();

      String function = 'v1/multi';
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      // Multi-Request senden mit Priority-Kontext
      RestApiHttpMetric metric = RestApiHttpMetric(function, HttpMethod.post);

      try {
        metric.start();

        callbacks.triggerLogEvent("Multi-Request send: $requestUri");
        callbacks.triggerLogEvent(
          "Multi-Request Body: ${requestsList.length} requests",
        );

        http.Response response = await _client
            .post(
              requestUri,
              headers: _getHeader(),
              body: jsonEncode(requestsList),
            )
            .timeout(
              Duration(
                minutes: 5,
              ), // Priority-spezifisches Timeout könnte hier angepasst werden
            );

        metric.responseCode = response.statusCode;
        metric.responsePayloadSize = response.body.length;
        metric.responseContentType = response.headers['content-type'];
        metric.stop();

        // Multi-Request-Antwort verarbeiten
        await _processMultiRequestResponse(response, requests);
      } finally {
        callbacks.triggerHttpMetricRecordedEvent(metric);
      }
    } catch (error) {
      // Bei Fehler alle wartenden Requests mit Einzelanfragen durchführen
      callbacks.triggerLogEvent(
        "Priority Multi-Request (${priority.name}) failed, falling back to individual requests: $error",
      );
      await _fallbackToIndividualRequests(requests);
    }
  }

  /// Verarbeitet die Antwort eines Multi-Requests
  Future<void> _processMultiRequestResponse(
    http.Response response,
    List<RestAPIBufferedRequest> requests,
  ) async {
    if (response.statusCode != 200) {
      throw HttpException(
        'Multi-Request failed with status ${response.statusCode}',
      );
    }

    try {
      dynamic responses = jsonDecode(response.body);

      List<dynamic> responseList = responses["data"] ?? [];

      // Die Antworten sollten in der gleichen Reihenfolge sein wie die Anfragen
      for (int i = 0; i < requests.length && i < responseList.length; i++) {
        var request = requests[i];
        var responseData = responseList[i];

        var responseResult = responseData['result'];
        var responseStatus = responseData['httpStatus'];

        if (!request.completer.isCompleted) {
          // Erfolgreiche Antwort erstellen
          http.Response individualResponse = http.Response(
            jsonEncode(responseResult),
            responseStatus,
            headers: {'content-type': 'application/json'},
          );

          request.completer.complete(individualResponse);
        }
      }

      // Falls weniger Antworten als Anfragen vorhanden sind
      for (int i = responses.length; i < requests.length; i++) {
        var request = requests[i];
        if (!request.completer.isCompleted) {
          await _retryAsSingleRequest(request);
        }
      }
    } catch (error) {
      // Bei Parsing-Fehlern alle Requests als Einzelanfragen wiederholen
      await _fallbackToIndividualRequests(requests);
    }
  }

  /// Fallback auf Einzelanfragen bei Multi-Request-Fehlern
  Future<void> _fallbackToIndividualRequests(
    List<RestAPIBufferedRequest> requests,
  ) async {
    for (var request in requests) {
      if (!request.completer.isCompleted) {
        await _retryAsSingleRequest(request);
      }
    }
  }

  /// Wiederholt eine Anfrage als Einzelanfrage
  Future<void> _retryAsSingleRequest(
    RestAPIBufferedRequest bufferedRequest,
  ) async {
    try {
      // Stelle sicher, dass die aktuellste Session-ID verwendet wird
      Map<String, String>? requestHeader = bufferedRequest.requestHeader;
      if (requestHeader != null && _loggedIn && _config.sessionId.isNotEmpty) {
        requestHeader = Map<String, String>.from(requestHeader);
        requestHeader['sessionid'] = _config.sessionId;
      }

      // Verwende _http() statt direkt request.execute() um Session-Handling zu erhalten
      http.Response response = await _http(
        bufferedRequest.method,
        bufferedRequest.requestUri,
        bufferedRequest.function,
        body: bufferedRequest.body,
        requestHeader: requestHeader,
        multiRetry: true,
      );

      bufferedRequest.completer.complete(response);
    } catch (error) {
      bufferedRequest.completer.completeError(error);
    }
  }

  /// Meldet den Benutzer in der Datenbank über '/v2/login' oder '/v2/login/secure' an
  ///
  /// Führt eine sichere Anmeldung mit RSA- oder AES-Verschlüsselung durch.
  /// Die Methode verwendet entweder v2/login (mit AES) oder v2/login/secure (mit RSA)
  /// je nach der Konfiguration der `v2Login`-Eigenschaft.
  ///
  /// [md5Password] - Das bereits als MD5-Hash verschlüsselte Passwort
  ///
  /// Returns: [RestApiLoginResponse] mit Session-ID und Anmeldestatus
  ///
  /// Throws: Exceptions definiert in [RestApiResponse] und [RestApiLoginResponse]
  ///
  /// Beispiel:
  /// ```dart
  /// String hashedPassword = "098f6bcd4621d373cade4e832627b4f6"; // MD5 von "test"
  /// RestApiLoginResponse response = await manager.login(hashedPassword);
  /// if (response.isOk) {
  ///   print("Anmeldung erfolgreich: ${response.sessionId}");
  /// }
  /// ```
  Future<RestApiLoginResponse> login(
    String md5Password, {
    String? twoFactorAuthToken,
    bool refreshSession = false,
  }) async {
    try {
      String v2Loginfunction = "v2/login";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$v2Loginfunction";
      Uri requestUri = _getUri(uriPath);

      Map<String, String> requestHeader = _getHeader(addSessionId: false);
      Map<String, dynamic> requestBodyMap = {};
      Map<String, dynamic> deviceMap = {};
      String bodyText;

      List<String> completeAppnames = [];
      completeAppnames.addAll(_config.appNames);
      completeAppnames.addAll(_config.additionalAppNames);

      requestBodyMap['user'] = _config.userName;
      requestBodyMap['pass'] = md5Password;
      if (twoFactorAuthToken != null) {
        requestBodyMap['2faToken'] = twoFactorAuthToken;
      }
      requestBodyMap['appNames'] = completeAppnames;
      if (_config.device != null) {
        deviceMap = _config.device!.toJson();
        requestBodyMap['device'] = deviceMap;
      }
      requestBodyMap['furtherencryption'] = false;

      RestApiLoginSecureKeyResponse secureKeyResponse;

      secureKeyResponse = await getLoginKey();

      if (!secureKeyResponse.isOk) {
        throw Exception("Secure Key can not be provided");
      }

      String serverPublicKey = secureKeyResponse.key;

      bodyText = await _getv2LoginBody(
        jsonEncode(requestBodyMap),
        serverPublicKey,
      );

      final response = RestApiLoginResponse(
        await _http(
          HttpMethod.post,
          requestUri,
          v2Loginfunction,
          handleSession: false,
          body: bodyText,
          requestHeader: requestHeader,
          login: true,
          refreshSession: refreshSession,
        ),
      );

      if (response.isOk) {
        _password = md5Password;
        _config.sessionId = response.sessionId;
        _loggedIn = true;
        _manualLoggedOut = false;
        callbacks.triggerSessionIdChangedEvent(_config.sessionId);
      }
      return (response);
    } catch (e) {
      _config.sessionId = "";
      callbacks.triggerSessionIdChangedEvent(_config.sessionId);
      rethrow;
    }
  }

  /// Überprüft die aktuelle Session über '/_CheckSession'
  ///
  /// Verifiziert, ob die aktuelle Session noch gültig ist.
  /// Diese Methode sollte regelmäßig aufgerufen werden, um sicherzustellen,
  /// dass die Session nicht abgelaufen ist.
  ///
  /// Returns: [RestApiResponse] mit dem Validierungsstatus der Session
  ///
  /// Throws: Exceptions definiert in [RestApiResponse]
  ///
  /// Beispiel:
  /// ```dart
  /// try {
  ///   RestApiResponse response = await manager.checkSession();
  ///   if (response.isOk) {
  ///     print("Session ist noch gültig");
  ///   }
  /// } catch (e) {
  ///   print("Session-Prüfung fehlgeschlagen: $e");
  /// }
  /// ```
  Future<RestApiResponse> checkSession() async {
    try {
      String function = "_CheckSession";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Überprüft den Webservice über '/CheckService' mit einer URI
  ///
  /// Statische Methode zur Überprüfung der Verfügbarkeit eines Webservices
  /// ohne eine aktive RestApiManager-Instanz. Nützlich für Service-Discovery
  /// oder Health-Checks.
  ///
  /// [requestUri] - Die vollständige URI zum Service-Endpunkt
  ///
  /// Returns: [RestApiCheckServiceResponse] mit Service-Status und -Informationen
  ///
  /// Beispiel:
  /// ```dart
  /// Uri serviceUri = Uri.parse("https://server.com:8080/dfapp/_CheckService");
  /// RestApiCheckServiceResponse response = await RestApiManager.checkServiceWithUri(serviceUri);
  /// if (response.isOk) {
  ///   print("Service ist verfügbar");
  /// }
  /// ```
  static Future<RestApiCheckServiceResponse> checkServiceWithUri(
    Uri requestUri,
  ) async {
    try {
      final response = RestApiCheckServiceResponse(
        await http.get(requestUri).timeout(const Duration(seconds: 10)),
      );
      return response;
    } on Exception {
      debugPrint("checkService failed");
      rethrow;
    }
  }

  /// Überprüft den aktuellen Webservice über '/CheckService'
  ///
  /// Prüft die Verfügbarkeit und den Status des konfigurierten Webservices.
  /// Diese Methode verwendet die bereits konfigurierte Server-URL der Instanz.
  ///
  /// Returns: [RestApiCheckServiceResponse] mit Service-Status und Datenbank-Informationen
  ///
  /// Throws: Exception bei Netzwerkfehlern oder Service-Problemen
  ///
  /// Beispiel:
  /// ```dart
  /// try {
  ///   RestApiCheckServiceResponse response = await manager.checkService();
  ///   if (response.isOk) {
  ///     print("Service verfügbar, Datenbanken: ${response.databases.length}");
  ///   }
  /// } catch (e) {
  ///   print("Service-Check fehlgeschlagen: $e");
  /// }
  /// ```
  Future<RestApiCheckServiceResponse> checkService() async {
    try {
      String function = "_CheckService";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      return RestApiCheckServiceResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
    } on Exception {
      debugPrint("checkService failed");
      rethrow;
    }
  }

  /// Synchronisierte Session-Erneuerung
  ///
  /// Verhindert mehrere parallele Login-Vorgänge, indem wartende Requests
  /// auf bereits laufende Login-Operationen warten. Dies löst das Problem
  /// bei Multi-Request-Fallbacks, wo mehrere Requests gleichzeitig eine
  /// Session-Erneuerung auslösen könnten.
  ///
  /// Returns: [RefreshSessionResponse] mit Session-Status und neuer Session-ID
  Future<RefreshSessionResponse> _synchronizedRefreshSession({
    int retryCount = 3,
    String twoFaToken = "",
  }) async {
    // Falls bereits ein Login läuft, warte darauf
    if (_ongoingLogin != null) {
      try {
        return await _ongoingLogin!;
      } catch (e) {
        // Falls der laufende Login fehlschlägt, setze auf null und starte neuen Versuch
        _ongoingLogin = null;
      }
    }

    // Starte neuen Login-Vorgang
    _ongoingLogin = _refreshSession(
      retryCount: retryCount,
      twoFaToken: twoFaToken,
    );

    try {
      RefreshSessionResponse result = await _ongoingLogin!;
      return result;
    } finally {
      // Login-Vorgang beendet - für nächste Requests verfügbar machen
      _ongoingLogin = null;
    }
  }

  /// Überprüft die Session-Gültigkeit und versucht eine Neu-Anmeldung
  ///
  /// Private Methode zur automatischen Session-Erneuerung bei ungültigen Sessions.
  /// Führt mehrere Login-Versuche durch, wenn die aktuelle Session abgelaufen ist.
  ///
  /// [retryCount] - Maximale Anzahl der Wiederholungsversuche (Standard: 3)
  ///
  /// Returns: [RefreshSessionResponse] mit Session-Status und neuer Session-ID
  ///
  /// Die Methode wird automatisch von der HTTP-Client-Logik aufgerufen,
  /// wenn eine SessionInvalidException oder TokenOrSessionIsMissingException
  /// auftritt.
  ///
  /// Beispiel der internen Verwendung:
  /// ```dart
  /// RefreshSessionResponse sessionResponse = await _refreshSession(retryCount: 3);
  /// if (sessionResponse.isActive) {
  ///   requestHeader['sessionid'] = sessionResponse.sessionId;
  /// }
  /// ```
  Future<RefreshSessionResponse> _refreshSession({
    int retryCount = 3,
    String twoFaToken = "",
  }) async {
    bool active = false;
    List<RestApiResponse> responses = [];
    int i = 0;
    String newSessionId = "";

    for (i = 1; i < retryCount; i++) {
      RestApiLoginResponse response = await login(
        _password,
        twoFactorAuthToken: twoFaToken,
        refreshSession: true,
      );
      responses.add(response);
      if (response.isOk) {
        active = true;
        newSessionId = response.sessionId;
        break;
      } else {
        sleep(const Duration(microseconds: 500));
      }
    }

    RefreshSessionResponse sessionResponse = RefreshSessionResponse(
      active,
      maxRetryCount: retryCount,
      retryCount: i,
      sessionId: newSessionId,
    );

    return (sessionResponse);
  }

  /// Ruft Ordner-Inhalte nach Ordner-Typ ab
  ///
  /// Lädt alle Dokumente und Unterordner eines bestimmten Ordner-Typs
  /// mit optionaler Paginierung und Suchfunktionalität.
  ///
  /// [folderType] - Der Typ des Ordners (z.B. "Eingang", "Postausgang", "Entwürfe")
  /// [reverseOrder] - Umgekehrte Sortierreihenfolge (Standard: false)
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Elemente pro Seite (Standard: aus Konfiguration)
  /// [query] - Suchtext zum Filtern der Ergebnisse
  ///
  /// Returns: [RestApiResponse] mit Ordner-Inhalten und Metadaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getFolderByType(
  ///   "Eingang",
  ///   page: 1,
  ///   perPage: 20,
  ///   query: "wichtig"
  /// );
  /// ```
  Future<RestApiResponse> getFolderByType(
    String folderType, {
    bool reverseOrder = false,
    int page = 0,
    int? perPage,
    String query = "",
  }) async {
    try {
      String function = "v1/folders/type";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$folderType";
      Map<String, String> params = {};

      if (reverseOrder) {
        params['reverseOrder'] = reverseOrder.toString();
      }
      params['perPage'] = (perPage ?? _config.perPageCount).toString();
      if (page > 0) {
        params['page'] = page.toString();
      }
      if (query.isNotEmpty) {
        params['query'] = query;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Führt eine Aktion ohne Buffer-Verarbeitung aus
  ///
  /// Diese Methode verwendet Zone-lokale Variablen, um sicherzustellen,
  /// dass nur die Requests in diesem spezifischen Execution-Context
  /// vom MultiRequest-Buffering ausgeschlossen werden. Gleichzeitige Requests
  /// in anderen Isolates oder Zones werden NICHT beeinflusst.
  ///
  /// [action] - Eine Funktion, die eine REST-API-Aktion ausführt und ein
  ///           RestApiResponse-Objekt oder eine Unterklasse davon zurückgibt
  ///
  /// Returns: Das Ergebnis der übergebenen Aktion ohne Pufferung
  ///
  /// Die Methode ist besonders nützlich für:
  /// - Kritische Aktionen, die sofort ausgeführt werden müssen
  /// - Anfragen, die nicht mit anderen Anfragen kombiniert werden können
  /// - Debug- oder Testzwecke, um Multi-Request zu umgehen
  ///
  /// **Wichtig:** Diese Methode beeinflusst nur Requests im aktuellen
  /// Execution-Context. Hintergrund-Requests oder parallele Requests
  /// werden weiterhin normal mit MultiRequest verarbeitet.
  ///
  /// Beispiel für einzelnen Request:
  /// ```dart
  /// RestApiResponse response = await manager.executeWithoutBuffering(() async {
  ///   return await manager.getFolderByType("Eingang");
  /// });
  /// ```
  ///
  /// Beispiel für mehrere Requests:
  /// ```dart
  /// List<RestApiResponse> responses = await manager.executeWithoutBuffering(() async {
  ///   return [
  ///     await manager.getFolderByType("Eingang"),
  ///     await manager.getFolderByType("Ausgang"),
  ///   ];
  /// });
  /// ```
  Future<T> executeWithoutBuffering<T>(Future<T> Function() action) async {
    // Wenn Multi-Request nicht aktiviert ist, einfach ausführen
    if (!_config.multiRequest) {
      return await action();
    }

    // Verwende runZoned um einen isolierten Context zu erstellen
    // Nur Requests innerhalb dieser Zone werden vom MultiRequest ausgeschlossen
    return await runZoned<Future<T>>(
      () => action(),
      zoneValues: {
        _skipBufferingZoneKey: true, // Setze das Skip-Flag nur für diese Zone
      },
    );
  }

  /// Führt eine Action mit einer bestimmten Request-Priorität aus
  ///
  /// Diese Methode erstellt einen Zone-isolierten Kontext mit der angegebenen
  /// Priorität. Alle API-Requests innerhalb dieser Zone werden mit der
  /// entsprechenden Priorität verarbeitet.
  ///
  /// **Priority-Verhalten:**
  /// - `RequestPriority.high`: Sofortige Verarbeitung, kein Buffering
  /// - `RequestPriority.normal`: Standard-Buffering (wie bisher)
  /// - `RequestPriority.low`: Erweiterte Pufferung für Hintergrund-Operationen
  ///
  /// **Wichtig:** Diese Methode beeinflusst nur Requests im aktuellen
  /// Execution-Context. Parallele Requests werden nicht beeinflusst.
  ///
  /// [action] - Die auszuführende Funktion mit API-Aufrufen
  /// [priority] - Die Priorität für alle Requests innerhalb der Action
  ///
  /// Beispiel für High-Priority Request:
  /// ```dart
  /// RestApiResponse response = await manager.executeWithPriority(() async {
  ///   return await manager.getFolderByType("Eingang");
  /// }, RequestPriority.high);
  /// ```
  ///
  /// Beispiel für Low-Priority Background Loading:
  /// ```dart
  /// List<RestApiResponse> backgroundData = await manager.executeWithPriority(() async {
  ///   return [
  ///     await manager.getFolderByType("Archiv"),
  ///     await manager.getSystemSettings(),
  ///   ];
  /// }, RequestPriority.low);
  /// ```
  Future<T> executeWithPriority<T>(
    Future<T> Function() action,
    RequestPriority priority,
  ) async {
    // Wenn Multi-Request nicht aktiviert ist, einfach ausführen
    if (!_config.multiRequest) {
      return await action();
    }

    // Priority-Zone erstellen
    return await runZoned<Future<T>>(
      () => action(),
      zoneValues: {_priorityZoneKey: priority},
    );
  }

  /// Führt Druck-Makros aus und ersetzt Platzhalter mit Objektdaten
  ///
  /// Verarbeitet Textvorlagen mit Makro-Platzhaltern und ersetzt diese
  /// mit Daten aus den angegebenen Objekten (Adresse, Vorgang, etc.).
  ///
  /// [text] - Der Text mit Makro-Platzhaltern (z.B. "Sehr geehrte {Adresse.Anrede}")
  /// [addressOid] - OID der Adresse für Adress-Makros
  /// [addressNrOid] - OID der Adressnummer
  /// [contactPersonOid] - OID der Kontaktperson
  /// [incidentOid] - OID des Vorgangs
  /// [objectOid] - OID eines allgemeinen Objekts
  ///
  /// Returns: [RestApiResponse] mit dem verarbeiteten Text
  ///
  /// Beispiel:
  /// ```dart
  /// String template = "Sehr geehrte/r {Adresse.Anrede} {Adresse.Name}";
  /// RestApiResponse response = await manager.postPrintMacrosExecute(
  ///   template,
  ///   addressOid: "12345"
  /// );
  /// ```
  Future<RestApiResponse> postPrintMacrosExecute(
    String text, {
    String addressOid = "",
    String addressNrOid = "",
    String contactPersonOid = "",
    String incidentOid = "",
    String objectOid = "",
  }) async {
    try {
      await _synchronizedRefreshSession();

      String function = "v1/printMacros/execute";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      bodyMap['text'] = text;
      if (addressOid.isNotEmpty) {
        bodyMap['address'] = addressOid;
      }
      if (addressNrOid.isNotEmpty) {
        bodyMap['addressNr'] = addressNrOid;
      }
      if (contactPersonOid.isNotEmpty) {
        bodyMap['contactPerson'] = contactPersonOid;
      }
      if (incidentOid.isNotEmpty) {
        bodyMap['incident'] = incidentOid;
      }
      if (objectOid.isNotEmpty) {
        bodyMap['object'] = objectOid;
      }
      body = json.encode(bodyMap);

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Ordner-Inhalte über die Objekt-ID (OID) ab
  ///
  /// Lädt den Inhalt eines spezifischen Ordners anhand seiner eindeutigen
  /// Objekt-ID mit Paginierung und Suchoptionen.
  ///
  /// [oid] - Die eindeutige Objekt-ID des Ordners
  /// [reverseOrder] - Umgekehrte Sortierreihenfolge (Standard: false)
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Elemente pro Seite (Standard: aus Konfiguration)
  /// [query] - Suchtext zum Filtern der Ergebnisse
  ///
  /// Returns: [RestApiResponse] mit Ordner-Inhalten und Dokumenten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getFolderByOid(
  ///   "folder-oid-12345",
  ///   query: "vertrag",
  ///   perPage: 50
  /// );
  /// ```
  Future<RestApiResponse> getFolderByOid(
    String oid, {
    bool reverseOrder = false,
    int page = 0,
    int? perPage,
    String query = "",
  }) async {
    try {
      String function = "v1/folders/oid";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$oid";
      Map<String, String> params = {};

      if (reverseOrder) {
        params['reverseOrder'] = reverseOrder.toString();
      }
      if (page > 0) {
        params['page'] = page.toString();
      }
      params['perPage'] = (perPage ?? _config.perPageCount).toString();
      if (query.isNotEmpty) {
        params['query'] = query;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Ordner-Inhalte über den Ordner-Pfad ab
  ///
  /// Lädt den Inhalt eines Ordners anhand seines hierarchischen Pfads
  /// im Dateisystem mit Paginierung und Suchfunktionen.
  ///
  /// [path] - Der vollständige Pfad zum Ordner (z.B. "/Projekte/2024/Projekt1")
  /// [reverseOrder] - Umgekehrte Sortierreihenfolge (Standard: false)
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Elemente pro Seite (Standard: aus Konfiguration)
  /// [query] - Suchtext zum Filtern der Ergebnisse
  ///
  /// Returns: [RestApiResponse] mit Ordner-Inhalten und Navigationsdaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getFolderByPath(
  ///   "/Dokumente/Verträge/2024",
  ///   reverseOrder: true,
  ///   query: "kunde"
  /// );
  /// ```
  Future<RestApiResponse> getFolderByPath(
    String path, {
    bool reverseOrder = false,
    int page = 0,
    int? perPage,
    String query = "",
  }) async {
    try {
      String encodedPath = Uri.encodeComponent(path);
      String function = "v1/folders/path";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$encodedPath";

      if (config.useFolderPathEncoding) {
        encodedPath = encodedPath.replaceAll('%5C', '%255C');
      }

      Map<String, String> params = {};
      if (reverseOrder) {
        params['reverseOrder'] = reverseOrder.toString();
      }
      if (page > 0) {
        params['page'] = page.toString();
      }
      params['perPage'] = (perPage ?? _config.perPageCount).toString();
      if (query.isNotEmpty) {
        params['query'] = query.toString();
      }

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Termine aus einem bestimmten Zeitraum ab
  ///
  /// Lädt alle Termine zwischen den angegebenen Datumsangaben
  /// mit optionaler Filterung nach Benutzer und Suchtext.
  ///
  /// [from] - Startzeit für den Zeitraum
  /// [to] - Endzeit für den Zeitraum
  /// [username] - Name des Kalender-Besitzers (leer = aktueller Benutzer)
  /// [query] - Suchtext für Termine (optional)
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Termine pro Seite (Standard: aus Konfiguration)
  ///
  /// Returns: [RestApiResponse] mit Termin-Liste und Metadaten
  ///
  /// Beispiel:
  /// ```dart
  /// DateTime start = DateTime.now();
  /// DateTime end = start.add(Duration(days: 7));
  /// RestApiResponse response = await manager.getAppointments(
  ///   start,
  ///   end,
  ///   username: "mueller",
  ///   query: "meeting"
  /// );
  /// ```
  Future<RestApiResponse> getAppointments(
    DateTime from,
    DateTime to, {
    String username = "",
    String? query,
    int page = 0,
    int? perPage,
  }) async {
    try {
      String function = "v1/appointments";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      params['from'] = from.toISOFormatString();
      params['to'] = to.toISOFormatString();
      params['page'] = page.toString();
      params['perPage'] = (perPage ?? _config.perPageCount).toString();
      if (username.isNotEmpty) {
        params['username'] = username;
      }
      if (query != null) {
        params['queryString'] = query;
      }
      params['serialization'] = "{\"type\":\"class\",\"style\":\"preview\"}";

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Erstellt einen neuen Termin im Kalender
  ///
  /// Legt einen neuen Kalendereintrag mit allen erforderlichen Informationen an.
  /// Unterstützt Teilnehmer, Erinnerungen, Terminserien und Benachrichtigungen.
  ///
  /// [from] - Startzeit des Termins
  /// [to] - Endzeit des Termins
  /// [title] - Titel des Termins
  /// [place] - Ort des Termins
  /// [description] - Beschreibung des Termins
  /// [owner] - Besitzer des Termins
  /// [remindBefore] - Erinnerung vor dem Termin (ISO-Duration)
  /// [remindAt] - Erinnerung zu bestimmter Zeit
  /// [wholeDay] - Ganztägiger Termin (Standard: false)
  /// [attendeesUserNames] - Liste der Teilnehmer-Benutzernamen
  /// [attendeesAddresses] - Liste der Teilnehmer-Adressen
  /// [attendeesEmails] - Liste der Teilnehmer-E-Mail-Adressen
  /// [isSerial] - Terminserie (Standard: false)
  /// [rrule] - Wiederholungsregel (iCalendar RRULE)
  ///
  /// Returns: [RestApiResponse] mit Termin-ID und Erstellungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.postAppointments(
  ///   DateTime.now().add(Duration(hours: 1)),
  ///   DateTime.now().add(Duration(hours: 2)),
  ///   title: "Team Meeting",
  ///   place: "Konferenzraum A",
  ///   attendeesUserNames: ["mueller", "schmidt"]
  /// );
  /// ```
  Future<RestApiResponse> postAppointments(
    DateTime from,
    DateTime to, {
    String title = "",
    String place = "",
    String description = "",
    String owner = "",
    ISODuration? remindBefore,
    DateTime? remindAt,
    bool wholeDay = false,
    bool group = false,
    List<String>? attendeesUserNames,
    List<String>? attendeesAddresses,
    List<String>? attendeesEmails,
    String notificationComment = "",
    bool notifyAllAttendees = false,
    bool isSerial = false,
    bool public = false,
    bool extern = false,
    int? type,
    int? occupancy,
    String rrule = "",
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      Map<String, dynamic> attendeesMap = {};
      String body;

      String function = "v1/appointments";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['from'] = from.toISOFormatString();
      bodyMap['to'] = to.toISOFormatString();
      bodyMap['title'] = title;
      bodyMap['place'] = place;
      bodyMap['description'] = description;
      bodyMap['owner'] = owner;
      if (remindBefore != null) {
        bodyMap['remindBefore'] = remindBefore.toISOFormatString();
      }
      if (remindAt != null) {
        bodyMap['remindAt'] = remindAt.toISOFormatString();
      }
      bodyMap['wholeDay'] = wholeDay;
      if (attendeesUserNames != null) {
        attendeesMap['users'] = attendeesUserNames;
      }
      if (attendeesAddresses != null) {
        attendeesMap['addresses'] = attendeesAddresses;
      }
      if (attendeesEmails != null) {
        attendeesMap['emails'] = attendeesEmails;
      }
      if (notificationComment.isNotEmpty) {
        attendeesMap['notificationComment'] = notificationComment;
      }
      if (notifyAllAttendees) {
        attendeesMap['notifyAllAttendees'] = notifyAllAttendees;
      }
      if (attendeesMap.isNotEmpty) {
        bodyMap['attendees'] = attendeesMap;
      }
      if (type != null) {
        bodyMap['type'] = type;
      }
      if (occupancy != null) {
        bodyMap['occupancy'] = occupancy;
      }
      bodyMap['isSerial'] = isSerial;
      bodyMap['public'] = public;
      bodyMap['extern'] = extern;
      if (rrule.isNotEmpty) {
        bodyMap['rrule'] = rrule;
      }

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to find next free date with given duration
  ///
  /// [from] Appointment start
  ///
  /// [to] Appointment end
  ///
  /// [searchArea] end date for search
  ///
  /// [users] checks free dates in user calenders
  Future<RestApiResponse> postAppointmentsNextFreeDate(
    DateTime from,
    DateTime to,
    DateTime searchArea,
    List<String> users,
  ) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;
      String function = "v1/appointments/nextFreeDate";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['from'] = from.toISOFormatString();
      bodyMap['to'] = to.toISOFormatString();
      bodyMap['searchArea'] = searchArea.toISOFormatString();
      bodyMap['users'] = users;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to reply to appointment invitation
  ///
  /// [id] OID or ~UUID of appointment or EMail appointment
  ///
  /// [action] (one of accept, tentative, decline) Possible actions for replying to appointments invitation
  ///
  /// [deleteAppointment] It allows to delete the appointment when the invitation is going to be declined
  Future<RestApiResponse> postAppointmentsInvitation(
    String id,
    String action,
    bool deleteAppointment,
  ) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;
      String function = "v1/appointments/$id/invitation";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$action";
      Uri requestUri = _getUri(uriPath);

      bodyMap['deleteAppointment'] = deleteAppointment;

      body = json.encode(bodyMap);

      function = "v1/appointments/id/invitation";
      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiObjectLockResponse> getLockObject(String id) async {
    try {
      String function = "v1/lock/object/$id";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiObjectLockResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  ///  This request allows to remove date from Termin series
  ///
  /// [id] OID or ~UUID of appointment (Termin series)
  ///
  /// [date] utc start date of the the appointment that gets deleted from Termin series
  Future<RestApiResponse> patchAppointmentsRemoveFromSeries(
    String id,
    DateTime date,
  ) async {
    try {
      String function = "v1/appointments/$id/removeFromSeries";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      Map<String, dynamic> bodyMap = {};
      bodyMap['date'] = date.toISOFormatString();
      String body = json.encode(bodyMap);

      function = "v1/appointments/id/removeFromSeries";
      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to edit an appointment
  ///
  /// [id] OID or ~UUID of appointment
  Future<RestApiResponse> patchAppointmentsUpdateAppointment(
    String id,
    DateTime from,
    DateTime to, {
    String title = "",
    String place = "",
    String description = "",
    String owner = "",
    ISODuration? remindBefore,
    DateTime? remindAt,
    bool wholeDay = false,
    bool group = false,
    List<String>? attendeesUserNames,
    List<String>? attendeesAddresses,
    List<String>? attendeesEmails,
    String notificationComment = "",
    bool notifyAllAttendees = false,
    bool isSerial = false,
    bool public = false,
    bool extern = false,
    int? type,
    int? occupancy,
    String rrule = "",
  }) async {
    try {
      Map<String, dynamic> attendeesMap = {};
      Map<String, dynamic> bodyMap = {};
      String body;
      String function = "v1/appointments/$id/updateAppointment";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['from'] = from.toISOFormatString();
      bodyMap['to'] = to.toISOFormatString();
      bodyMap['title'] = title;
      bodyMap['place'] = place;
      bodyMap['description'] = description;
      bodyMap['owner'] = owner;
      if (remindBefore != null && remindBefore != const ISODuration(year: 0)) {
        bodyMap['remindBefore'] = remindBefore.toISOFormatString();
      }
      if (remindAt != null) {
        bodyMap['remindAt'] = remindAt.toISOFormatString();
      }
      bodyMap['wholeDay'] = wholeDay;
      if (attendeesUserNames != null) {
        attendeesMap['users'] = attendeesUserNames;
      }
      if (attendeesAddresses != null) {
        attendeesMap['addresses'] = attendeesAddresses;
      }
      if (attendeesEmails != null) {
        attendeesMap['emails'] = attendeesEmails;
      }
      if (notificationComment.isNotEmpty) {
        attendeesMap['notificationComment'] = notificationComment;
      }
      if (notifyAllAttendees) {
        attendeesMap['notifyAllAttendees'] = notifyAllAttendees;
      }
      if (attendeesMap.isNotEmpty) {
        bodyMap['attendees'] = attendeesMap;
      }
      bodyMap['isSerial'] = isSerial;
      bodyMap['public'] = public;
      bodyMap['extern'] = extern;
      if (type != null) {
        bodyMap['type'] = type;
      }
      if (occupancy != null) {
        bodyMap['occupancy'] = occupancy;
      }
      if (rrule.isNotEmpty) {
        bodyMap['rrule'] = rrule;
      }

      body = json.encode(bodyMap);

      function = "v1/appointments/id/updateAppointment";
      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to create Termin series exception
  ///
  /// [id] OID or ~UUID of the Termin series appointment
  ///
  /// [exceptionFrom] start date of the appointment
  ///
  /// optional fields: new appointment data
  Future<RestApiResponse> patchAppointmentsCreateException(
    String id,
    DateTime exceptionFrom,
    DateTime from,
    DateTime to, {
    String title = "",
    String place = "",
    String description = "",
    String owner = "",
    ISODuration remindBefore = const ISODuration(year: 0),
    DateTime? remindAt,
    bool wholeDay = false,
    bool group = false,
    List<String>? attendeesUserNames,
    List<String>? attendeesAddresses,
    List<String>? attendeesEmails,
    String notificationComment = "",
    bool notifyAllAttendees = false,
    bool isSerial = false,
    bool public = false,
    bool extern = false,
    int? type,
    int? occupancy,
    String rrule = "",
  }) async {
    try {
      Map<String, dynamic> attendeesMap = {};
      Map<String, dynamic> bodyMap = {};
      Map<String, dynamic> exceptionBody = {};
      String body;
      String function = "v1/appointments/$id/createException";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['exceptionFrom'] = exceptionFrom.toISOFormatString();
      exceptionBody['from'] = from.toISOFormatString();
      exceptionBody['to'] = to.toISOFormatString();
      if (title.isNotEmpty) {
        exceptionBody['title'] = title;
      }
      if (place.isNotEmpty) {
        exceptionBody['place'] = place;
      }
      if (description.isNotEmpty) {
        exceptionBody['description'] = description;
      }
      if (owner.isNotEmpty) {
        exceptionBody['owner'] = owner;
      }
      if (remindBefore != const ISODuration(year: 0)) {
        exceptionBody['remindBefore'] = remindBefore.toISOFormatString();
      }
      if (remindAt != null) {
        exceptionBody['remindAt'] = remindAt.toISOFormatString();
      }
      if (wholeDay) {
        exceptionBody['wholeDay'] = wholeDay;
      }
      if (group) {
        exceptionBody['group'] = wholeDay;
      }
      if (attendeesUserNames != null) {
        attendeesMap['users'] = attendeesUserNames;
      }
      if (attendeesAddresses != null) {
        attendeesMap['addresses'] = attendeesAddresses;
      }
      if (attendeesEmails != null) {
        attendeesMap['emails'] = attendeesEmails;
      }
      if (notificationComment.isNotEmpty) {
        attendeesMap['notificationComment'] = notificationComment;
      }
      if (notifyAllAttendees) {
        attendeesMap['notifyAllAttendees'] = notifyAllAttendees;
      }
      if (attendeesMap.isNotEmpty) {
        exceptionBody['attendees'] = attendeesMap;
      }
      if (isSerial) {
        exceptionBody['isSerial'] = isSerial;
      }
      exceptionBody['public'] = public;
      exceptionBody['extern'] = extern;
      if (type != null) {
        exceptionBody['type'] = type;
      }
      if (occupancy != null) {
        exceptionBody['occupancy'] = occupancy;
      }
      if (rrule.isNotEmpty) {
        exceptionBody['rrule'] = rrule;
      }
      bodyMap['exceptionBody'] = exceptionBody;

      body = json.encode(bodyMap);

      function = "v1/appointments/id/createException";
      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Erstellt eine neue E-Mail als Entwurf
  ///
  /// Legt eine neue E-Mail mit allen erforderlichen Headern und Inhalten an.
  /// Die E-Mail wird als Entwurf gespeichert und kann später bearbeitet oder gesendet werden.
  ///
  /// [uuid] - Eindeutige UUID für die E-Mail (optional)
  /// [from] - Absender-Adresse (Standard: "-")
  /// [to] - Liste der Empfänger-Adressen
  /// [cc] - Liste der CC-Empfänger
  /// [bcc] - Liste der BCC-Empfänger
  /// [subject] - Betreff der E-Mail
  /// [htmlContent] - HTML-Inhalt der E-Mail
  /// [plainContent] - Plain-Text-Inhalt der E-Mail
  /// [template] - Vorlagen-Name für automatische Inhaltserstellung
  /// [templateData] - Daten für die Vorlagen-Verarbeitung
  /// [attachments] - Liste der Anhänge (Format: [{"name": "file.pdf", "data": "base64..."}])
  /// [priorityValue] - Prioritätswert (1=hoch, 3=normal, 5=niedrig)
  /// [acknowledgementRequired] - Lesebestätigung erforderlich
  ///
  /// Returns: [RestApiResponse] mit E-Mail-ID und Erstellungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.postMail(
  ///   to: ["kunde@example.com"],
  ///   subject: "Angebot Nr. 12345",
  ///   htmlContent: "<p>Sehr geehrte Damen und Herren...</p>",
  ///   priorityValue: 2
  /// );
  /// ```
  Future<RestApiResponse> postMail({
    String uuid = "",
    String from = "-",
    List<String>? to,
    List<String>? cc,
    List<String>? bcc,
    String name = "-",
    String description = "-",
    String subject = "-",
    String htmlContent = "-",
    String plainContent = "-",
    String template = "",
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = "normal",
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    DateTime? startTime,
    String action = "",
    String actions = "",
    String serialization = "",
    bool assignAddress = false,
    bool assignProject = false,
    bool assignProduct = false,
    bool assignContact = false,
    bool sendAssignReceiver = false,
    bool assignAction = false,
  }) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/mail";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      if (action.isNotEmpty) {
        params['action'] = action.toString();
      }
      if (actions.isNotEmpty) {
        params['actions'] = actions;
      }
      if (serialization.isNotEmpty) {
        params['serialization'] = serialization;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['~UUID'] = uuid;
      bodyMap['from'] = from;
      if (to != null) bodyMap['to'] = to;
      if (cc != null) bodyMap['cc'] = cc;
      if (bcc != null) bodyMap['bcc'] = bcc;
      bodyMap['name'] = name;
      bodyMap['description'] = description;
      bodyMap['subject'] = subject;
      bodyMap['htmlContent'] = htmlContent;
      bodyMap['plainContent'] = plainContent;
      if (template != "") bodyMap['template'] = template;
      if (templateData != null) bodyMap['templateData'] = templateData;
      if (attachments != null) bodyMap['attachments'] = attachments;
      bodyMap['acknowledgementRequired'] = acknowledgementRequired;
      bodyMap['keepCalendar'] = keepCalendar;
      if (startTime != null) {
        bodyMap['startTime'] = startTime.toISOFormatString();
      }
      priorityBody['priorityValue'] = priorityValue;
      priorityBody['priorityText'] = priorityText;
      bodyMap['assignAddresses'] = assignAddress;
      bodyMap['assignProjects'] = assignProject;
      bodyMap['assignProducts'] = assignProduct;
      bodyMap['assignContacts'] = assignContact;
      bodyMap['assignActions'] = assignAction;
      bodyMap['sendAssignReceiver'] = sendAssignReceiver;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to update existing an email, either the uuid or oid are needed
  Future<RestApiResponse> patchMail({
    String uuid = "",
    String oid = "",
    String from = "-",
    List<String>? to,
    List<String>? cc,
    List<String>? bcc,
    String name = "-",
    String description = "-",
    String subject = "-",
    String htmlContent = "-",
    String plainContent = "-",
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = "normal",
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    bool convertImageDataSrcToFileSrc = false,
    DateTime? startTime,
    String actions = "",
  }) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/mail";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      if (actions.isNotEmpty) {
        params['actions'] = actions;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      // ~UUID oder ~ObjectID oder ~OidOrUuid
      if (uuid.isNotEmpty) bodyMap['~UUID'] = uuid;
      if (oid.isNotEmpty) bodyMap['~ObjectID'] = oid;
      bodyMap['from'] = from;
      if (to != null) bodyMap['to'] = to;
      if (cc != null) bodyMap['cc'] = cc;
      if (bcc != null) bodyMap['bcc'] = bcc;
      bodyMap['name'] = name;
      bodyMap['description'] = description;
      bodyMap['subject'] = subject;
      bodyMap['htmlContent'] = htmlContent;
      bodyMap['plainContent'] = plainContent;
      if (templateData != null) bodyMap['templateData'] = templateData;
      if (attachments != null) bodyMap['attachments'] = attachments;
      bodyMap['acknowledgementRequired'] = acknowledgementRequired;
      bodyMap['convertImageDataSrcToFileSrc'] = convertImageDataSrcToFileSrc;
      bodyMap['keepCalendar'] = keepCalendar;
      if (startTime != null) {
        bodyMap['startTime'] = startTime.toISOFormatString();
      }
      priorityBody['priorityValue'] = priorityValue;
      priorityBody['priorityText'] = priorityText;
      bodyMap['priority'] = priorityBody;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to update existing email and send it (when body does not contain any OID a new mail is beeing created)
  Future<RestApiResponse> postMailSend({
    String uuid = "",
    String oid = "",
    String from = "-",
    List<String>? to,
    List<String>? cc,
    List<String>? bcc,
    String name = "-",
    String description = "-",
    String subject = "-",
    String htmlContent = "-",
    String plainContent = "-",
    String template = "",
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = "normal",
    bool convertImageDataSrcToFileSrc = false,
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    DateTime? startTime,
    String action = "",
    String actions = "",
  }) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/mail/send";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      if (action.isNotEmpty) params['action'] = action.toString();
      // example: [{ "type": "sendObject", "toUser": "demo", "text": "Hello world"}]
      if (actions.isNotEmpty) params['actions'] = actions;

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['~UUID'] = uuid;
      bodyMap['~ObjectID'] = oid;
      bodyMap['from'] = from;
      if (to != null) bodyMap['to'] = to;
      if (cc != null) bodyMap['cc'] = cc;
      if (bcc != null) bodyMap['bcc'] = bcc;
      bodyMap['name'] = name;
      bodyMap['description'] = description;
      bodyMap['subject'] = subject;
      bodyMap['htmlContent'] = htmlContent;
      bodyMap['plainContent'] = plainContent;
      if (template != "") bodyMap['template'] = template;
      if (templateData != null) bodyMap['templateData'] = templateData;
      if (attachments != null) bodyMap['attachments'] = attachments;
      bodyMap['acknowledgementRequired'] = acknowledgementRequired;
      bodyMap['convertImageDataSrcToFileSrc'] = convertImageDataSrcToFileSrc;
      bodyMap['keepCalendar'] = keepCalendar;
      if (startTime != null) {
        bodyMap['startTime'] = startTime.toISOFormatString();
      }
      priorityBody['priorityValue'] = priorityValue;
      priorityBody['priorityText'] = priorityText;
      bodyMap['priority'] = priorityBody;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> saveMailAttachmentsToDatabase(
    String mailOid, {
    bool saveAll = false,
    bool extractSingularZipFile = false,
    List<int> indices = const [],
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/mail/saveAttachmentsToDB";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$mailOid";

      Uri requestUri = _getUri(uriPath);

      bodyMap['saveAll'] = saveAll;
      bodyMap['extractSingularZipFile'] = extractSingularZipFile;
      bodyMap['indices'] = indices;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// not implemented in df-restapi
  ///
  /// This request allows to reply for an email
  Future<RestApiResponse> postMailReply(
    String sourceMailOid, {
    String uuid = "",
    String oid = "",
    String from = "-",
    String to = "-",
    String cc = "-",
    String bcc = "-",
    String name = "-",
    String description = "-",
    String subject = "-",
    String htmlContent = "-",
    String plainContent = "-",
    String template = "",
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = "normal",
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    DateTime? startTime,
    String action = "",
    String actions = "",
    String serialization = "",
    bool assignAddress = false,
    bool assignProject = false,
    bool assignProduct = false,
    bool assignContact = false,
    bool sendAssignReceiver = false,
    bool assignAction = false,
  }) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/mail/reply";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$sourceMailOid";
      Map<String, String> params = {};

      if (action.isNotEmpty) params['action'] = action.toString();
      if (actions.isNotEmpty) params['actions'] = actions;
      if (serialization.isNotEmpty) params['serialization'] = serialization;

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['~UUID'] = uuid;
      bodyMap['~ObjectID'] = oid;
      bodyMap['from'] = from;
      bodyMap['to'] = to;
      bodyMap['cc'] = cc;
      bodyMap['bcc'] = bcc;
      bodyMap['name'] = name;
      bodyMap['description'] = description;
      bodyMap['subject'] = subject;
      bodyMap['htmlContent'] = htmlContent;
      bodyMap['plainContent'] = plainContent;
      if (template != "") bodyMap['template'] = template;
      if (templateData != null) bodyMap['templateData'] = templateData;
      if (attachments != null) bodyMap['attachments'] = attachments;
      bodyMap['acknowledgementRequired'] = acknowledgementRequired;
      bodyMap['keepCalendar'] = keepCalendar;
      if (startTime != null) {
        bodyMap['startTime'] = startTime.toISOFormatString();
      }
      priorityBody['priorityValue'] = priorityValue;
      priorityBody['priorityText'] = priorityText;
      bodyMap['priority'] = priorityBody;
      bodyMap['assignAddresses'] = assignAddress;
      bodyMap['assignProjects'] = assignProject;
      bodyMap['assignProducts'] = assignProduct;
      bodyMap['assignContacts'] = assignContact;
      bodyMap['assignActions'] = assignAction;
      bodyMap['sendAssignReceiver'] = sendAssignReceiver;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// not implemented in df-restapi
  ///
  /// This request allows to reply all for an email
  Future<RestApiResponse> postMailReplyAll(
    String sourceMailOid, {
    String uuid = "",
    String oid = "",
    String from = "-",
    String to = "-",
    String cc = "-",
    String bcc = "-",
    String name = "-",
    String description = "-",
    String subject = "-",
    String htmlContent = "-",
    String plainContent = "-",
    String template = "",
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = "normal",
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    DateTime? startTime,
    String action = "",
    String actions = "",
    String serialization = "",
    bool assignAddress = false,
    bool assignProject = false,
    bool assignProduct = false,
    bool assignContact = false,
    bool sendAssignReceiver = false,
    bool assignAction = false,
  }) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/mail/replyAll";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$sourceMailOid";
      Map<String, String> params = {};

      if (action.isNotEmpty) params['action'] = action.toString();
      if (actions.isNotEmpty) params['actions'] = actions;
      if (serialization.isNotEmpty) params['serialization'] = serialization;

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['~UUID'] = uuid;
      bodyMap['~ObjectID'] = oid;
      bodyMap['from'] = from;
      bodyMap['to'] = to;
      bodyMap['cc'] = cc;
      bodyMap['bcc'] = bcc;
      bodyMap['name'] = name;
      bodyMap['description'] = description;
      bodyMap['subject'] = subject;
      bodyMap['htmlContent'] = htmlContent;
      bodyMap['plainContent'] = plainContent;
      if (template != "") bodyMap['template'] = template;
      if (templateData != null) bodyMap['templateData'] = templateData;
      if (attachments != null) bodyMap['attachments'] = attachments;
      bodyMap['acknowledgementRequired'] = acknowledgementRequired;
      bodyMap['keepCalendar'] = keepCalendar;
      if (startTime != null) {
        bodyMap['startTime'] = startTime.toISOFormatString();
      }
      priorityBody['priorityValue'] = priorityValue;
      priorityBody['priorityText'] = priorityText;
      bodyMap['priority'] = priorityBody;
      bodyMap['assignAddresses'] = assignAddress;
      bodyMap['assignProjects'] = assignProject;
      bodyMap['assignProducts'] = assignProduct;
      bodyMap['assignContacts'] = assignContact;
      bodyMap['assignActions'] = assignAction;
      bodyMap['sendAssignReceiver'] = sendAssignReceiver;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// not implemented in df-restapi
  ///
  /// This request allows to forward an email
  Future<RestApiResponse> postMailForward(
    String sourceMailOid, {
    String uuid = "",
    String oid = "",
    String from = "-",
    List<String>? to,
    List<String>? cc,
    List<String>? bcc,
    String name = "-",
    String description = "-",
    String subject = "-",
    String htmlContent = "-",
    String plainContent = "-",
    String template = "",
    Map<String, dynamic>? templateData,
    List<Map<String, dynamic>>? attachments,
    int priorityValue = 3,
    String priorityText = "normal",
    bool acknowledgementRequired = false,
    bool keepCalendar = false,
    DateTime? startTime,
    String action = "",
    String actions = "",
    String serialization = "",
    bool assignAddress = false,
    bool assignProject = false,
    bool assignProduct = false,
    bool assignContact = false,
    bool sendAssignReceiver = false,
    bool assignAction = false,
  }) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;
      String function = "v1/mail/forward";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$sourceMailOid";
      Map<String, String> params = {};

      if (action.isNotEmpty) params['action'] = action.toString();
      if (actions.isNotEmpty) params['actions'] = actions;
      if (serialization.isNotEmpty) params['serialization'] = serialization;

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['~UUID'] = uuid;
      bodyMap['~ObjectID'] = oid;
      bodyMap['from'] = from;
      if (to != null) bodyMap['to'] = to;
      if (cc != null) bodyMap['cc'] = cc;
      if (bcc != null) bodyMap['bcc'] = bcc;
      bodyMap['name'] = name;
      bodyMap['description'] = description;
      bodyMap['subject'] = subject;
      bodyMap['htmlContent'] = htmlContent;
      bodyMap['plainContent'] = plainContent;
      if (template != "") bodyMap['template'] = template;
      if (templateData != null) bodyMap['templateData'] = templateData;
      if (attachments != null) bodyMap['attachments'] = attachments;
      bodyMap['acknowledgementRequired'] = acknowledgementRequired;
      bodyMap['keepCalendar'] = keepCalendar;
      if (startTime != null) {
        bodyMap['startTime'] = startTime.toISOFormatString();
      }
      priorityBody['priorityValue'] = priorityValue;
      priorityBody['priorityText'] = priorityText;
      bodyMap['priority'] = priorityBody;
      bodyMap['assignAddresses'] = assignAddress;
      bodyMap['assignProjects'] = assignProject;
      bodyMap['assignProducts'] = assignProduct;
      bodyMap['assignContacts'] = assignContact;
      bodyMap['assignActions'] = assignAction;
      bodyMap['sendAssignReceiver'] = sendAssignReceiver;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getMailAccounts() async {
    try {
      String function = "v1/mail/accounts";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getUserEmailSignatures() async {
    try {
      String function = "v1/userEmailSignatures";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Lädt eine Datei anhand ihrer Objekt-ID herunter
  ///
  /// Ruft den Dateiinhalt und die Metadaten einer gespeicherten Datei ab.
  /// Die Methode prüft automatisch die Session und lädt dann die vollständige Datei.
  ///
  /// [oid] - Die eindeutige Objekt-ID der Datei
  ///
  /// Returns: [RestApiFileResponse] mit Dateiinhalt, MIME-Type und Metadaten
  ///
  /// Throws: Exception bei Netzwerkfehlern oder ungültiger OID
  ///
  /// Beispiel:
  /// ```dart
  /// try {
  ///   RestApiFileResponse response = await manager.getFile("file-oid-12345");
  ///   if (response.isOk) {
  ///     Uint8List fileData = response.data;
  ///     String fileName = response.fileName;
  ///     String mimeType = response.mimeType;
  ///     // Datei speichern oder verarbeiten
  ///   }
  /// } catch (e) {
  ///   print("Datei-Download fehlgeschlagen: $e");
  /// }
  /// ```
  Future<RestApiFileResponse> getFile(String oid) async {
    String function = "v1/file";
    String uriPath =
        "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$oid";

    RestApiHttpMetric metric = RestApiHttpMetric(function, HttpMethod.get);

    try {
      Uri requestUri = _getUri(uriPath);

      metric.start();

      http.Response httpResponse = await http
          .get(requestUri, headers: _getHeader())
          .timeout(const Duration(seconds: 60));
      final response = RestApiFileResponse(httpResponse);

      metric.responseCode = httpResponse.statusCode;
      metric.responsePayloadSize = httpResponse.contentLength;
      metric.responseContentType = httpResponse.headers['content-type'];
      metric.stop();

      return (response);
    } catch (_) {
      rethrow;
    } finally {
      callbacks.triggerHttpMetricRecordedEvent(metric);
    }
  }

  /// Generiert eine Vorschau-Darstellung eines Objekts
  ///
  /// Erstellt eine Vorschau (Thumbnail) für Dokumente, Bilder oder andere Objekte
  /// in der angegebenen Größe und Qualität.
  ///
  /// [objectOid] - Die Objekt-ID des Elements für die Vorschau
  /// [parameters] - Format-Parameter (z.B. "200x150" für Größe, "jpg" für Format)
  /// [page] - Seitenzahl bei mehrseitigen Dokumenten (Standard: 0)
  /// [keepRatio] - Seitenverhältnis beibehalten (Standard: true)
  ///
  /// Returns: [Uint8List] mit den Bilddaten der Vorschau oder null bei Fehlern
  ///
  /// Beispiel:
  /// ```dart
  /// Uint8List? previewData = await manager.getPreview(
  ///   "document-oid-12345",
  ///   "300x200.jpg",
  ///   page: 1,
  ///   keepRatio: true
  /// );
  /// if (previewData != null) {
  ///   // Vorschau anzeigen
  ///   Image.memory(previewData);
  /// }
  /// ```
  Future<Uint8List?> getPreview(
    String objectOid,
    String parameters, {
    int page = 0,
    bool keepRatio = true,
  }) async {
    String function = "v1/preview";
    RestApiHttpMetric metric = RestApiHttpMetric(function, HttpMethod.get);

    try {
      Uint8List? bytes;

      String keepRatioPath = keepRatio ? "/keep-ratio" : "/";
      String objectOidPath = "/$objectOid";
      String pagePath = "/$page";

      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$parameters$keepRatioPath$objectOidPath$pagePath";
      Uri requestUri = _getUri(uriPath);

      metric.start();

      http.Response httpResponse = await http
          .get(requestUri, headers: _getHeader())
          .timeout(const Duration(seconds: 60));

      metric.responseCode = httpResponse.statusCode;
      metric.responsePayloadSize = httpResponse.contentLength;
      metric.responseContentType = httpResponse.headers['content-type'];
      metric.stop();

      if (httpResponse.statusCode == 200) {
        bytes = httpResponse.bodyBytes;
      }

      return bytes;
    } catch (_) {
      rethrow;
    } finally {
      callbacks.triggerHttpMetricRecordedEvent(metric);
    }
  }

  /// Ruft die DF-Konfiguration der Anwendung ab
  ///
  /// Lädt die aktuelle Konfiguration der DF-Anwendung vom Server,
  /// einschließlich Einstellungen, Berechtigungen und Systemparameter.
  ///
  /// Returns: [RestApiResponse] mit der vollständigen Konfiguration
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getDFConfig();
  /// if (response.isOk) {
  ///   Map<String, dynamic> config = response.data;
  ///   print("App-Version: ${config['version']}");
  /// }
  /// ```
  Future<RestApiResponse> getDFConfig() async {
    try {
      String function = "v1/execute/xDFAppGetConfig";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);
      String requestBodyJson = '{}';

      final response = RestApiResponse(
        await _http(
          HttpMethod.post,
          requestUri,
          function,
          body: requestBodyJson,
        ),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft E-Mail-Adress-Vorschläge basierend auf Suchtext ab
  ///
  /// Sucht nach E-Mail-Adressen in der Datenbank und gibt passende
  /// Vorschläge für die Auto-Vervollständigung zurück.
  ///
  /// [searchtext] - Der Suchtext für die E-Mail-Adress-Suche
  ///
  /// Returns: [RestApiResponse] mit einer Liste von E-Mail-Vorschlägen
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getEmailSuggestions("max");
  /// if (response.isOk) {
  ///   List emails = response.data['suggestions'];
  ///   // emails enthält: ["max@example.com", "maxmustermann@company.de"]
  /// }
  /// ```
  Future<RestApiResponse> getEmailSuggestions(String searchtext) async {
    try {
      String function = "v1/execute/xDFAppGetEMailAddressSuggestions";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);
      String body = "";

      Map<String, dynamic> bodyMap = {};
      bodyMap["searchtext"] = searchtext;

      body = jsonEncode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

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
  /// RestApiResponse response = await manager.createDemoAccount("demo123");
  /// if (response.isOk) {
  ///   print("Demo-Konto erfolgreich erstellt");
  /// }
  /// ```
  Future<RestApiResponse> createDemoAccount(String password) async {
    try {
      String function = "v1/DF/CreateDemoUser";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);
      String body = "";

      Map<String, dynamic> bodyMap = {};
      bodyMap["deviceId"] = _config.device?.deviceId;
      bodyMap["password"] = password;

      body = jsonEncode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Objektdaten anhand der Objekt-ID ab
  ///
  /// Lädt die vollständigen Daten eines bestimmten Objekts aus der Datenbank
  /// mit optionaler Klassenfilterung und Serialisierungsoptionen.
  ///
  /// [objectOid] - Die eindeutige Objekt-ID
  /// [className] - Optionale Klassenfilterung (z.B. "Vorgang", "Adresse")
  /// [serialization] - Serialisierungsoptionen für die Datenausgabe
  ///
  /// Returns: [RestApiResponse] mit den Objektdaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getObject(
  ///   "obj-12345",
  ///   className: "Vorgang",
  ///   serialization: '{"type":"full"}'
  /// );
  /// if (response.isOk) {
  ///   Map<String, dynamic> objectData = response.data;
  /// }
  /// ```
  Future<RestApiResponse> getObject(
    String objectOid, {
    String className = "",
    String serialization = "",
  }) async {
    try {
      String function = "v1/object";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$objectOid";
      Map<String, String> params = {};

      if (className.isNotEmpty) params['class'] = className;
      if (serialization.isNotEmpty) params['serialization'] = serialization;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft ungelesene Dokumente des aktuellen Benutzers ab
  ///
  /// Lädt alle Dokumente, die vom aktuellen Benutzer noch nicht gelesen wurden.
  /// Hilfreich für Benachrichtigungen und To-Do-Listen.
  ///
  /// Returns: [RestApiResponse] mit der Liste ungelesener Dokumente
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getPersonalUnreadDocuments();
  /// if (response.isOk) {
  ///   List unreadDocs = response.data['documents'];
  ///   print("${unreadDocs.length} ungelesene Dokumente");
  /// }
  /// ```
  Future<RestApiResponse> getPersonalUnreadDocuments() async {
    try {
      String function = "v1/personal/unreadDocuments";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft persönliche Aufgaben des aktuellen Benutzers ab
  ///
  /// Lädt alle dem aktuellen Benutzer zugewiesenen Aufgaben und Aktionen.
  /// Enthält sowohl offene als auch abgeschlossene Aufgaben.
  ///
  /// Returns: [RestApiResponse] mit der Liste persönlicher Aufgaben
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getPersonalMyTasks();
  /// if (response.isOk) {
  ///   List tasks = response.data['tasks'];
  ///   print("${tasks.length} Aufgaben gefunden");
  /// }
  /// ```
  Future<RestApiResponse> getPersonalMyTasks() async {
    try {
      String function = "v1/personal/myTasks";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft die Hierarchie von Aktionen/Vorgängen ab
  ///
  /// Lädt die vollständige Baum-Struktur von Unter-Aktionen eines Vorgangs
  /// mit konfigurierbarer Tiefe und Serialisierungsoptionen.
  ///
  /// [oid] - Die Objekt-ID des Haupt-Vorgangs
  /// [deepLevel] - Maximale Verschachtelungstiefe (-1 = unbegrenzt)
  /// [serialization] - Serialisierungsoptionen für die Ausgabe
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit der hierarchischen Aktions-Struktur
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getIncidentTree(
  ///   "incident-12345",
  ///   deepLevel: 3,
  ///   serialization: '{"includeChildren": true}'
  /// );
  /// ```
  Future<RestApiResponse> getIncidentTree(
    String oid, {
    int deepLevel = -1,
    String serialization = "",
    String rightsControlKey = "",
  }) async {
    try {
      String function = "v1/incidentTree";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$oid";
      Map<String, String> params = {};

      if (deepLevel != -1) params['deepLevel'] = deepLevel.toString();
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Leert den Papierkorb des aktuellen Benutzers
  ///
  /// Löscht alle Objekte aus dem persönlichen Papierkorb endgültig.
  /// Diese Aktion kann nicht rückgängig gemacht werden.
  ///
  /// Returns: [RestApiResponse] mit dem Status der Papierkorb-Leerung
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.patchPersonalEmptyRecycleBin();
  /// if (response.isOk) {
  ///   print("Papierkorb erfolgreich geleert");
  /// }
  /// ```
  Future<RestApiResponse> patchPersonalEmptyRecycleBin() async {
    try {
      String function = "v1/personal/emptyRecycleBin";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Erstellt ein neues Objekt in der Datenbank
  ///
  /// Legt ein neues Objekt der angegebenen Klasse mit den bereitgestellten
  /// Daten an. Unterstützt verschiedene Speichermodi und Aktionen.
  ///
  /// [className] - Der Name der Objektklasse (z.B. "Vorgang", "Adresse", "Projekt")
  /// [body] - JSON-String mit den Objektdaten
  /// [storeMode] - Speichermodus (0=DBOModifyMember, 10=DBOSet)
  /// [serialization] - Serialisierungsoptionen für die Antwort
  /// [actions] - Zusätzliche Aktionen nach dem Speichern
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit der neuen Objekt-ID
  ///
  /// Beispiel:
  /// ```dart
  /// String objectData = jsonEncode({
  ///   "name": "Neuer Vorgang",
  ///   "description": "Beschreibung des Vorgangs"
  /// });
  /// RestApiResponse response = await manager.postObject(
  ///   "Vorgang",
  ///   objectData
  /// );
  /// ```
  Future<RestApiResponse> postObject(
    String className,
    String body, {
    int storeMode = 0,
    String serialization = "",
    String actions = "",
    String rightsControlKey = "",
  }) async {
    try {
      String function = "v1/object";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$className";
      Map<String, String> params = {};

      // default 0: DBOModifyMember... | 10: DBOSet...
      if (storeMode != 0) params['storeMode'] = storeMode.toString();
      // example: [{ "type": "sendObject", "toUser": "demo", "text": "Hello world"}]
      if (actions.isNotEmpty) params['actions'] = actions;
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Erstellt eine Nachricht als Entwurf
  ///
  /// Legt eine neue interne Nachricht an mehrere Benutzer als Entwurf an.
  /// Die Nachricht kann später bearbeitet oder direkt gesendet werden.
  ///
  /// [toUsers] - Liste der Empfänger-Benutzernamen
  /// [text] - Nachrichtentext
  /// [name] - Titel/Name der Nachricht
  /// [description] - Zusätzliche Beschreibung
  /// [addToIncomingFolder] - In Eingangsordner hinzufügen (Standard: true)
  /// [originalOid] - OID der ursprünglichen Nachricht (bei Antworten)
  /// [uuid] - Eindeutige UUID für die Nachricht
  /// [serialization] - Serialisierungsoptionen
  /// [rightsControlKey] - Berechtigungsschlüssel
  /// [actions] - Zusätzliche Aktionen
  ///
  /// Returns: [RestApiResponse] mit der Nachrichten-ID
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.postMessage(
  ///   ["mueller", "schmidt"],
  ///   "Wichtige Information zum Projekt...",
  ///   name: "Projekt-Update"
  /// );
  /// ```
  Future<RestApiResponse> postMessage(
    List<String> toUsers,
    String text, {
    String name = "",
    String description = "",
    bool addToIncomingFolder = true,
    String originalOid = "",
    String uuid = "",
    String serialization = "",
    String rightsControlKey = "",
    String actions = "",
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/message";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (actions.isNotEmpty) params['actions'] = actions;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['toUsers'] = toUsers;
      bodyMap['text'] = text;
      if (uuid.isNotEmpty) bodyMap['~UUID'] = uuid;
      if (name.isNotEmpty) bodyMap['name'] = name;
      if (description.isNotEmpty) bodyMap['description'] = description;
      if (addToIncomingFolder) {
        bodyMap['addToIncomingFolder'] = addToIncomingFolder;
      }
      if (originalOid.isNotEmpty) bodyMap['originalOid'] = originalOid;
      if (name.isNotEmpty) bodyMap['name'] = name;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Erstellt und sendet eine Nachricht direkt
  ///
  /// Legt eine neue interne Nachricht an und sendet sie sofort an die
  /// angegebenen Empfänger ohne Zwischenspeicherung als Entwurf.
  ///
  /// [toUsers] - Liste der Empfänger-Benutzernamen
  /// [text] - Nachrichtentext
  /// [name] - Titel/Name der Nachricht
  /// [description] - Zusätzliche Beschreibung
  /// [addToIncomingFolder] - In Eingangsordner hinzufügen (Standard: true)
  /// [originalOid] - OID der ursprünglichen Nachricht (bei Antworten)
  /// [uuid] - Eindeutige UUID für die Nachricht
  /// [serialization] - Serialisierungsoptionen
  /// [rightsControlKey] - Berechtigungsschlüssel
  /// [actions] - Zusätzliche Aktionen
  ///
  /// Returns: [RestApiResponse] mit dem Sendestatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.postMessageSend(
  ///   ["team@firma.de"],
  ///   "Das Meeting findet um 14:00 statt.",
  ///   name: "Meeting-Erinnerung"
  /// );
  /// ```
  Future<RestApiResponse> postMessageSend(
    List<String> toUsers,
    String text, {
    String name = "",
    String description = "",
    bool addToIncomingFolder = true,
    String originalOid = "",
    String uuid = "",
    String serialization = "",
    String rightsControlKey = "",
    String actions = "",
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/message/send";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (actions.isNotEmpty) params['actions'] = actions;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['toUsers'] = toUsers;
      bodyMap['text'] = text;
      if (uuid.isNotEmpty) bodyMap['~UUID'] = uuid;
      if (name.isNotEmpty) bodyMap['name'] = name;
      if (description.isNotEmpty) bodyMap['description'] = description;
      if (addToIncomingFolder) {
        bodyMap['addToIncomingFolder'] = addToIncomingFolder;
      }
      if (originalOid.isNotEmpty) bodyMap['originalOid'] = originalOid;
      if (name.isNotEmpty) bodyMap['name'] = name;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Bearbeitet eine Entwurfs-Nachricht
  ///
  /// Aktualisiert eine bestehende Nachricht, die als Entwurf gespeichert ist.
  /// Die Nachricht kann später gesendet oder weiter bearbeitet werden.
  ///
  /// [oid] - Die Objekt-ID der zu bearbeitenden Nachricht
  /// [toUsers] - Liste der Empfänger-Benutzernamen
  /// [text] - Aktualisierter Nachrichtentext
  /// [name] - Neuer Titel/Name der Nachricht
  /// [description] - Aktualisierte Beschreibung
  /// [addToIncomingFolder] - In Eingangsordner hinzufügen (Standard: true)
  /// [originalOid] - OID der ursprünglichen Nachricht (bei Antworten)
  /// [uuid] - Eindeutige UUID für die Nachricht
  /// [serialization] - Serialisierungsoptionen
  /// [rightsControlKey] - Berechtigungsschlüssel
  ///
  /// Returns: [RestApiResponse] mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.patchMessage(
  ///   "msg-12345",
  ///   ["team@firma.de"],
  ///   "Aktualisierte Nachricht...",
  ///   name: "Korrigierte Mitteilung"
  /// );
  /// ```
  Future<RestApiResponse> patchMessage(
    String oid,
    List<String> toUsers,
    String text, {
    String name = "",
    String description = "",
    bool addToIncomingFolder = true,
    String originalOid = "",
    String uuid = "",
    String serialization = "",
    String rightsControlKey = "",
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/message";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$oid";
      Map<String, String> params = {};

      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['toUsers'] = toUsers;
      bodyMap['text'] = text;
      if (uuid.isNotEmpty) bodyMap['~UUID'] = uuid;
      if (name.isNotEmpty) bodyMap['name'] = name;
      if (description.isNotEmpty) bodyMap['description'] = description;
      if (addToIncomingFolder) {
        bodyMap['addToIncomingFolder'] = addToIncomingFolder;
      }
      if (originalOid.isNotEmpty) bodyMap['originalOid'] = originalOid;
      if (name.isNotEmpty) bodyMap['name'] = name;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Bearbeitet und sendet eine Nachricht direkt
  ///
  /// Aktualisiert eine bestehende Nachricht und sendet sie sofort an die
  /// angegebenen Empfänger. Kombiniert Bearbeitung und Versand in einem Schritt.
  ///
  /// [oid] - Die Objekt-ID der zu bearbeitenden und sendenden Nachricht
  /// [toUsers] - Liste der Empfänger-Benutzernamen
  /// [text] - Aktualisierter Nachrichtentext
  /// [name] - Neuer Titel/Name der Nachricht
  /// [description] - Aktualisierte Beschreibung
  /// [addToIncomingFolder] - In Eingangsordner hinzufügen (Standard: true)
  /// [originalOid] - OID der ursprünglichen Nachricht (bei Antworten)
  /// [uuid] - Eindeutige UUID für die Nachricht
  /// [serialization] - Serialisierungsoptionen
  /// [rightsControlKey] - Berechtigungsschlüssel
  ///
  /// Returns: [RestApiResponse] mit dem Sendestatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.patchMessageSend(
  ///   "msg-12345",
  ///   ["empfaenger@firma.de"],
  ///   "Finale Version der Nachricht",
  ///   name: "Wichtige Mitteilung - Final"
  /// );
  /// ```
  Future<RestApiResponse> patchMessageSend(
    String oid,
    List<String> toUsers,
    String text, {
    String name = "",
    String description = "",
    bool addToIncomingFolder = true,
    String originalOid = "",
    String uuid = "",
    String serialization = "",
    String rightsControlKey = "",
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/message/send";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$oid";
      Map<String, String> params = {};

      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['toUsers'] = toUsers;
      bodyMap['text'] = text;
      if (uuid.isNotEmpty) bodyMap['~UUID'] = uuid;
      if (name.isNotEmpty) bodyMap['name'] = name;
      if (description.isNotEmpty) bodyMap['description'] = description;
      if (addToIncomingFolder) {
        bodyMap['addToIncomingFolder'] = addToIncomingFolder;
      }
      if (originalOid.isNotEmpty) bodyMap['originalOid'] = originalOid;
      if (name.isNotEmpty) bodyMap['name'] = name;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Erstellt einen Unterordner
  ///
  /// Legt einen neuen Ordner als Unterordner eines bestehenden Ordners an.
  /// Unterstützt verschiedene Ordnertypen und hierarchische Strukturen.
  ///
  /// [folderName] - Name des neuen Ordners
  /// [parentFolder] - ID oder Pfad des übergeordneten Ordners
  /// [parentFolderSourceType] - Typ des übergeordneten Ordners (Standard: path)
  ///
  /// Returns: [RestApiResponse] mit der neuen Ordner-ID
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.postFolders(
  ///   "Neuer Unterordner",
  ///   "/Dokumente/Projekte",
  ///   parentFolderSourceType: RestApiFolderType.path
  /// );
  /// ```
  Future<RestApiResponse> postFolders(
    String folderName,
    String parentFolder, {
    RestApiDOCUframeFolderType parentFolderSourceType =
        RestApiDOCUframeFolderType.path,
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/folders";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['folderName'] = folderName;
      bodyMap['parentFolder'] = parentFolder;
      bodyMap['parentFolderSourceType'] = parentFolderSourceType.value;
      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Löscht einen Ordner
  ///
  /// Entfernt einen Ordner und optional seinen gesamten Inhalt aus dem System.
  /// Diese Aktion kann nicht rückgängig gemacht werden.
  ///
  /// [path] - Der vollständige Pfad zum zu löschenden Ordner
  ///
  /// Returns: [RestApiResponse] mit dem Löschstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.deleteFolders("/Temp/Alter_Ordner");
  /// if (response.isOk) {
  ///   print("Ordner erfolgreich gelöscht");
  /// }
  /// ```
  Future<RestApiResponse> deleteFolders(String path) async {
    try {
      String function = "v1/folders";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};
      if (path.isNotEmpty) params['path'] = path;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.delete, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Benennt einen Ordner um
  ///
  /// Ändert den Namen eines bestehenden Ordners ohne Änderung der Struktur
  /// oder des Inhalts.
  ///
  /// [oid] - Die Objekt-ID des umzubenennenden Ordners
  /// [newName] - Der neue Name für den Ordner
  ///
  /// Returns: [RestApiResponse] mit dem Umbenennungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.patchFoldersRename(
  ///   "folder-oid-12345",
  ///   "Neuer Ordnername"
  /// );
  /// ```
  Future<RestApiResponse> patchFoldersRename(String oid, String newName) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/folders/rename";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$oid";
      Uri requestUri = _getUri(uriPath);

      bodyMap['folderName'] = newName;
      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Fügt Dokumente zu einem Ordner hinzu
  ///
  /// Verknüpft eine Liste von Dokumenten mit einem bestimmten Ordner.
  /// Die Dokumente bleiben an ihrem ursprünglichen Speicherort.
  ///
  /// [folderType] - Der Typ des Zielordners
  /// [folderId] - Die ID des Zielordners
  /// [documentOids] - Liste der Dokument-OIDs zum Hinzufügen
  /// [className] - Klassenname für spezielle Ordnertypen (Favoriten, Historie)
  ///
  /// Returns: [RestApiResponse] mit dem Hinzufügungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.patchFoldersAdd(
  ///   RestApiFolderType.path,
  ///   "/Projekte/Projekt1",
  ///   ["doc-123", "doc-456", "doc-789"]
  /// );
  /// ```
  Future<RestApiResponse> patchFoldersAdd(
    RestApiDOCUframeFolderType folderType,
    String folderId,
    List<String> documentOids, {
    String className = "",
  }) async {
    try {
      Map<String, dynamic> documentsMap = {};
      String body;
      String folderTypeEncoded = Uri.encodeComponent(folderType.value);
      String folderIdEncoded = Uri.encodeComponent(folderId);
      String function = "v1/folders/add";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$folderTypeEncoded/$folderIdEncoded";
      Map<String, String> params = {};

      // class: In case one would like to add something from favorite or history it is necessary to provide the class of objects you would like to add
      if (className.isNotEmpty) params['class'] = className;
      Uri requestUri = _getUri(uriPath, params: params);

      documentsMap['documents'] = documentOids;
      body = json.encode(documentsMap);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Entfernt Dokumente aus einem Ordner
  ///
  /// Entfernt die Verknüpfung von Dokumenten zu einem Ordner.
  /// Optional können die Dokumente in den Papierkorb verschoben werden.
  ///
  /// [folderType] - Der Typ des Quellordners
  /// [folderId] - Die ID des Quellordners
  /// [documentOids] - Liste der zu entfernenden Dokument-OIDs
  /// [className] - Klassenname für spezielle Ordnertypen (Favoriten, Historie)
  /// [moveToTrashBin] - Dokumente in Papierkorb verschieben (Standard: true)
  /// [deep] - Tiefe Entfernung aus Unterordnern (Standard: false)
  ///
  /// Returns: [RestApiResponse] mit dem Entfernungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.patchFoldersRemoveDocuments(
  ///   RestApiFolderType.oid,
  ///   "folder-oid-12345",
  ///   ["doc-123", "doc-456"],
  ///   moveToTrashBin: false
  /// );
  /// ```
  Future<RestApiResponse> patchFoldersRemoveDocuments(
    RestApiDOCUframeFolderType folderType,
    String folderId,
    List<String> documentOids, {
    String className = "",
    bool moveToTrashBin = true,
    deep = false,
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String folderTypeEncoded = Uri.encodeComponent(folderType.value);
      String folderIdEncoded = Uri.encodeComponent(folderId);
      String function = "v1/folders/remove";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$folderTypeEncoded/$folderIdEncoded";
      Map<String, String> params = {};

      // class: In case one would like to remove something from favorite or history it is necessary to provide the class of objects you would like to remove
      if (className.isNotEmpty) params['class'] = className;
      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['documents'] = documentOids;
      bodyMap['moveToTrashBin'] = moveToTrashBin;
      bodyMap['deep'] = deep;
      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Kopiert oder verschiebt Dokumente zwischen Ordnern
  ///
  /// Transferiert Dokumente von einem Quellordner zu einem Zielordner.
  /// Unterstützt sowohl Kopieren als auch Verschieben von Dokumenten.
  ///
  /// [destinationFolderSourceType] - Typ des Zielordners
  /// [destinationFolderId] - ID des Zielordners
  /// [documentOids] - Liste der zu kopierenden/verschiebenden Dokument-OIDs
  /// [sourceFolderSourceType] - Typ des Quellordners (optional)
  /// [sourceFolderId] - ID des Quellordners (optional)
  /// [cut] - true = verschieben, false = kopieren (Standard: true)
  ///
  /// Returns: [RestApiResponse] mit dem Transfer-Status
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.patchFoldersCopyDocuments(
  ///   RestApiFolderType.path,
  ///   "/Archiv/2024",
  ///   ["doc-123", "doc-456"],
  ///   sourceFolderSourceType: RestApiFolderType.path,
  ///   sourceFolderId: "/Temp",
  ///   cut: true // verschieben
  /// );
  /// ```
  Future<RestApiResponse> patchFoldersCopyDocuments(
    RestApiDOCUframeFolderType destinationFolderSourceType,
    String destinationFolderId,
    List<String> documentOids, {
    RestApiDOCUframeFolderType? sourceFolderSourceType,
    String? sourceFolderId,
    bool cut = true,
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/folders/copyDocuments";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";

      Uri requestUri = _getUri(uriPath);

      bodyMap['destinationFolderSourceType'] =
          destinationFolderSourceType.value;
      bodyMap['destinationFolder'] = destinationFolderId;
      if (sourceFolderSourceType != null) {
        bodyMap['sourceFolderSourceType'] = sourceFolderSourceType.value;
      }
      if (sourceFolderId != null) bodyMap['sourceFolder'] = sourceFolderId;
      bodyMap['documents'] = documentOids;
      bodyMap['cut'] = cut;
      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Markiert Dokumente als gelesen oder ungelesen
  ///
  /// Ändert den Lesestatus von Dokumenten für den aktuellen Benutzer.
  /// Hilfreich für die Verwaltung von Benachrichtigungen und To-Do-Listen.
  ///
  /// [ids] - Liste von Dokument-OIDs oder UUIDs
  /// [read] - true = als gelesen markieren, false = als ungelesen (Standard: true)
  ///
  /// Returns: [RestApiResponse] mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// // Dokumente als gelesen markieren
  /// RestApiResponse response = await manager.putDocsRead(
  ///   ["doc-123", "doc-456"],
  ///   read: true
  /// );
  ///
  /// // Dokumente als ungelesen markieren
  /// await manager.putDocsRead(["doc-789"], read: false);
  /// ```
  Future<RestApiResponse> putDocsRead(
    List<String> ids, {
    bool read = true,
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/docs/read";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['read'] = read;
      bodyMap['ids'] = ids;
      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.put, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Markiert Dokumente als nicht mehr neu
  ///
  /// Entfernt Dokumente aus der Liste der neuen Dokumente für den aktuellen Benutzer.
  /// Wird verwendet, um die "Neu"-Kennzeichnung von Dokumenten zu entfernen.
  ///
  /// [ids] - Liste von Dokument-OIDs oder UUIDs
  ///
  /// Returns: [RestApiResponse] mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.putDocsNotNew(
  ///   ["doc-123", "doc-456", "doc-789"]
  /// );
  /// if (response.isOk) {
  ///   print("Dokumente als 'nicht neu' markiert");
  /// }
  /// ```
  Future<RestApiResponse> putDocsNotNew(List<String> ids) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/docs/removeDocFromNewDocuments";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['ids'] = ids;
      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.put, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Verwaltet die Objekthistorie des Benutzers
  ///
  /// Fügt Objekte zur Benutzerhistorie hinzu oder löscht komplette Klassenhistorien.
  /// Die Historie wird für schnellen Zugriff auf kürzlich verwendete Objekte verwendet.
  ///
  /// [ids] - Liste von Objekt-OIDs oder UUIDs
  /// [action] - "add" zum Hinzufügen, "remove" zum Löschen (Standard: "add")
  /// [className] - Klassenname zum Löschen der gesamten Klassenhistorie
  ///
  /// Returns: [RestApiResponse] mit dem Aktualisierungsstatus
  ///
  /// Beispiele:
  /// ```dart
  /// // Objekte zur Historie hinzufügen
  /// await manager.putDocsHistory(["obj-123", "obj-456"]);
  ///
  /// // Komplette Vorgangs-Historie löschen
  /// await manager.putDocsHistory(
  ///   ["dummy-id"],
  ///   action: "remove",
  ///   className: "Vorgang"
  /// );
  /// ```
  Future<RestApiResponse> putDocsHistory(
    List<String> ids, {
    String action = "add",
    String className = "",
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/docs/history";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['action'] = action;
      bodyMap['ids'] = ids;

      if (className.isNotEmpty) {
        bodyMap['className'] = className;
      }

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.put, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Bearbeitet ein bestehendes Objekt
  ///
  /// Aktualisiert die Daten eines vorhandenen Objekts in der Datenbank
  /// mit verschiedenen Speichermodi und Sicherheitsrichtlinien.
  ///
  /// [objectOid] - Die Objekt-ID des zu bearbeitenden Objekts
  /// [body] - JSON-String mit den aktualisierten Objektdaten
  /// [storeMode] - Speichermodus (0=DBOModifyMember, 10=DBOSet)
  /// [storeSecurityPolice] - Sicherheitsrichtlinie (0=EQ, 10=GT_NOLIST, etc.)
  /// [serialization] - Serialisierungsoptionen für die Antwort
  /// [actions] - Zusätzliche Aktionen nach dem Speichern
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// String updatedData = jsonEncode({
  ///   "name": "Aktualisierter Name",
  ///   "status": "In Bearbeitung"
  /// });
  /// RestApiResponse response = await manager.patchObject(
  ///   "obj-12345",
  ///   updatedData,
  ///   storeMode: 10
  /// );
  /// ```
  Future<RestApiResponse> patchObject(
    String objectOid,
    String body, {
    int storeMode = 0,
    int storeSecurityPolice = 0,
    String serialization = "",
    String actions = "",
    String rightsControlKey = "",
  }) async {
    try {
      String function = "v1/object";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$objectOid";
      Map<String, String> params = {};

      // default 0: DBOModifyMember... | 10: DBOSet...
      if (storeMode != 0) params['storeMode'] = storeMode.toString();
      // 0	EQ | 10 GT_NOLIST | 20	GT | 30	ANY_NOLIST | 40	ANY | 50	DIFF_NOLIST | 60	DIFF
      if (storeSecurityPolice != 0) {
        params['storeSecurityPolice'] = storeSecurityPolice.toString();
      }
      // example: [{ "type": "sendObject", "toUser": "demo", "text": "Hello world"}]
      if (actions.isNotEmpty) params['actions'] = actions;
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Löscht ein Objekt aus der Datenbank
  ///
  /// Entfernt ein Objekt permanent oder verschiebt es in den Papierkorb,
  /// abhängig von den Systemeinstellungen und Aktionen.
  ///
  /// [objectOid] - Die Objekt-ID des zu löschenden Objekts
  /// [actions] - Zusätzliche Aktionen beim Löschen (z.B. Benachrichtigungen)
  ///
  /// Returns: [RestApiResponse] mit dem Löschstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.deleteObject("obj-12345");
  /// if (response.isOk) {
  ///   print("Objekt erfolgreich gelöscht");
  /// }
  /// ```
  Future<RestApiResponse> deleteObject(
    String objectOid, {
    String actions = "",
  }) async {
    try {
      String function = "v1/object";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$objectOid";
      Uri requestUri;
      Map<String, String> params = {};

      if (actions.isNotEmpty) params['actions'] = actions;
      requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.delete, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft eine Liste von Objekten einer bestimmten Klasse ab
  ///
  /// Lädt alle Objekte einer spezifizierten Klasse mit Filterung,
  /// Paginierung und Suchfunktionalität.
  ///
  /// [className] - Name der Objektklasse (z.B. "Vorgang", "Adresse", "Projekt")
  /// [query] - Suchfilter für die Objektliste
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Objekte pro Seite (Standard: aus Konfiguration)
  /// [serialization] - Serialisierungsoptionen für die Ausgabe
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit der Objektliste und Metadaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getObjects(
  ///   "Vorgang",
  ///   query: "status:offen",
  ///   page: 1,
  ///   perPage: 25
  /// );
  /// if (response.isOk) {
  ///   List objects = response.data['data'];
  /// }
  /// ```
  Future<RestApiResponse> getObjects(
    String className, {
    String query = "",
    int page = 0,
    int? perPage,
    String serialization = "",
    String rightsControlKey = "",
  }) async {
    try {
      String function = "v1/objects";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$className";
      Map<String, String> params = {};

      if (query.isNotEmpty) params['query'] = query.toString();
      if (page != 0) params['page'] = page.toString();
      params['perPage'] = (perPage ?? _config.perPageCount).toString();
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Bearbeitet mehrere Objekte einer Klasse gleichzeitig
  ///
  /// Aktualisiert alle Objekte einer bestimmten Klasse, die den Suchkriterien
  /// entsprechen, mit den gleichen Daten. Massenbearbeitung von Objekten.
  ///
  /// [className] - Name der Objektklasse für die Massenbearbeitung
  /// [query] - Suchfilter zur Auswahl der zu bearbeitenden Objekte
  /// [body] - JSON-String mit den Aktualisierungsdaten
  /// [storeMode] - Speichermodus (0=DBOModifyMember, 10=DBOSet)
  /// [storeSecurityPolice] - Sicherheitsrichtlinie für die Bearbeitung
  /// [serialization] - Serialisierungsoptionen für die Antwort
  /// [actions] - Zusätzliche Aktionen nach dem Speichern
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit dem Status der Massenbearbeitung
  ///
  /// Beispiel:
  /// ```dart
  /// String updateData = jsonEncode({"status": "archiviert"});
  /// RestApiResponse response = await manager.patchObjects(
  ///   "Vorgang",
  ///   query: "created:<2023-01-01",
  ///   body: updateData
  /// );
  /// ```
  Future<RestApiResponse> patchObjects(
    String className, {
    String query = "",
    String body = "",
    int storeMode = 0,
    int storeSecurityPolice = 0,
    String serialization = "",
    String actions = "",
    String rightsControlKey = "",
  }) async {
    try {
      String function = "v1/objects";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$className";
      Map<String, String> params = {};

      if (query.isNotEmpty) params['query'] = query.toString();
      if (actions.isNotEmpty) params['actions'] = actions;
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }
      if (storeSecurityPolice != 0) {
        params['storeSecurityPolice'] = storeSecurityPolice.toString();
      }
      if (storeMode != 0) params['storeMode'] = storeMode.toString();

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Anruflisten und Telefonie-Daten ab
  ///
  /// Lädt Anrufinformationen, Anruflisten und Telefonie-bezogene Daten
  /// mit Filterung und Paginierung.
  ///
  /// [query] - Suchfilter für Anrufdaten
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Einträge pro Seite (Standard: aus Konfiguration)
  /// [serialization] - Serialisierungsoptionen für die Ausgabe
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit Anrufdaten und Telefonie-Informationen
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getCalls(
  ///   query: "direction:incoming",
  ///   page: 1
  /// );
  /// if (response.isOk) {
  ///   List calls = response.data['calls'];
  /// }
  /// ```
  Future<RestApiResponse> getCalls({
    String query = "",
    int page = 0,
    int? perPage,
    String serialization = "",
    String rightsControlKey = "",
  }) async {
    try {
      String function = "v1/calls";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      if (query.isNotEmpty) params['query'] = query.toString();
      if (page != 0) params['page'] = page.toString();
      params['perPage'] = (perPage ?? _config.perPageCount).toString();
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft die Modell-Struktur der Datenbank ab
  ///
  /// Lädt die Strukturinformationen für Datenbank-Klassen und deren Eigenschaften.
  /// Nützlich für dynamische UI-Generierung und Datenvalidierung.
  ///
  /// [classes] - Komma-getrennte Liste spezifischer Klassen (optional)
  /// [baseClasses] - Basis-Klassen für Vererbungshierarchie
  /// [skipMembers] - Eigenschaften überspringen (Standard: false)
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit Modell-Strukturdaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getModelStructure(
  ///   classes: "Vorgang,Adresse,Projekt"
  /// );
  /// ```
  Future<RestApiResponse> getModelStructure({
    String classes = "",
    String baseClasses = "",
    bool skipMembers = false,
    String rightsControlKey = "",
  }) async {
    try {
      String function = "v1/model/structure";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      if (classes.isNotEmpty) params['classes'] = classes;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft erweiterte Modell-Strukturinformationen ab
  ///
  /// Lädt detaillierte Strukturinformationen für das erweiterte Datenmodell
  /// mit konfigurierbaren Optionen für Klassen und Member-Daten.
  ///
  /// [classes] - Komma-getrennte Liste spezifischer Klassen (optional)
  /// [baseClasses] - Basis-Klassen für Vererbungshierarchie
  /// [skipMembers] - Member-Eigenschaften überspringen (Standard: false)
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit erweiterten Modell-Strukturdaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getExtModelStructure(
  ///   classes: "Vorgang,Adresse",
  ///   skipMembers: false
  /// );
  /// ```
  Future<RestApiResponse> getExtModelStructure({
    String classes = "",
    String baseClasses = "",
    bool skipMembers = false,
    String rightsControlKey = "",
  }) async {
    try {
      String function = "v1/extModel/structure";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      if (classes.isNotEmpty) params['classes'] = classes;
      if (baseClasses.isNotEmpty) params['baseClasses'] = baseClasses;
      if (skipMembers) params['skipMembers'] = skipMembers.toString();
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Machine Learning Modell-Daten ab
  ///
  /// Lädt spezialisierte Datenstrukturen für Machine Learning Anwendungen
  /// mit flexibler Konfiguration über Header- und Body-Parameter.
  ///
  /// [headerClasses] - Klassen für Header-Parameter (Query-String)
  /// [bodyClasses] - Klassen für Request-Body (POST-Parameter)
  /// [skipMembers] - Member-Eigenschaften überspringen (Standard: false)
  ///
  /// Returns: [RestApiResponse] mit ML-spezifischen Modell-Daten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getExtModelML(
  ///   headerClasses: ["Vorgang"],
  ///   bodyClasses: ["Adresse", "Projekt"],
  ///   skipMembers: true
  /// );
  /// ```
  Future<RestApiResponse> getExtModelML({
    List<String>? headerClasses,
    List<String>? bodyClasses,
    bool skipMembers = false,
  }) async {
    try {
      String function = "v1/extModel/ml";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      if (headerClasses != null && headerClasses.isNotEmpty) {
        params['ml'] = jsonEncode(headerClasses);
      }
      if (skipMembers) params['skipMembers'] = skipMembers.toString();

      if (bodyClasses != null && bodyClasses.isNotEmpty) {
        bodyMap['ml'] = bodyClasses;
      }
      body = bodyMap.isNotEmpty ? json.encode(bodyMap) : "";

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(
          bodyClasses == null ? HttpMethod.get : HttpMethod.post,
          requestUri,
          function,
          body: body,
        ),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Datenbank-Index-Informationen ab
  ///
  /// Lädt Informationen über verfügbare Datenbank-Indizes für bessere
  /// Performance-Optimierung und Abfrage-Planung.
  ///
  /// [classes] - Komma-getrennte Liste spezifischer Klassen (optional)
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit Index-Informationen und Performance-Daten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getExtModelIndexes(
  ///   classes: "Vorgang,Adresse"
  /// );
  /// if (response.isOk) {
  ///   List indexes = response.data['indexes'];
  /// }
  /// ```
  Future<RestApiResponse> getExtModelIndexes({
    String classes = "",
    String rightsControlKey = "",
  }) async {
    try {
      String function = "v1/extModel/indexes";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      if (classes.isNotEmpty) params['classes'] = classes;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }
      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Wörterbuch-Daten aus dem Modell ab
  ///
  /// Lädt sprachspezifische Wörterbuch-Daten für Übersetzungen und
  /// lokalisierte Bezeichnungen innerhalb der Anwendung.
  ///
  /// [dict] - Name des anzufragenden Wörterbuchs
  /// [langID] - Sprach-ID für spezifische Lokalisierung (optional)
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: [RestApiResponse] mit Wörterbuch-Daten und Übersetzungen
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getModelDict(
  ///   "status_labels",
  ///   langID: "de-DE"
  /// );
  /// if (response.isOk) {
  ///   Map<String, String> translations = response.data;
  /// }
  /// ```
  Future<RestApiResponse> getModelDict(
    String dict, {
    String langID = "",
    String rightsControlKey = "",
  }) async {
    try {
      String function = "v1/model/dict";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      params['dict'] = dict;
      if (langID.isNotEmpty) params['langID'] = langID;
      if (rightsControlKey.isNotEmpty) {
        params['rightsControlKey'] = rightsControlKey;
      }

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Meldet den Benutzer vom System ab
  ///
  /// Beendet die aktuelle Session und setzt alle Session-bezogenen
  /// Variablen zurück. Sendet eine Abmelde-Anfrage an den Server.
  ///
  /// Returns: [RestApiResponse] mit dem Abmeldestatus
  ///
  /// Nach der Abmeldung werden automatisch folgende Aktionen ausgeführt:
  /// - Session-ID wird geleert
  /// - Anmeldestatus wird auf false gesetzt
  /// - sessionIdChangedEvent wird ausgelöst
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.logout();
  /// if (response.isOk) {
  ///   print("Erfolgreich abgemeldet");
  /// }
  /// ```
  Future<RestApiResponse> logout() async {
    try {
      String function = "v1/logout";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      _loggedIn = false;
      _manualLoggedOut = true;
      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    } finally {
      _config.sessionId = "";
      callbacks.triggerSessionIdChangedEvent(_config.sessionId);
    }
  }

  /// Lädt eine Datei auf den Server hoch
  ///
  /// Überträgt eine lokale Datei oder Web-Datei auf den Server und erstellt
  /// optional ein Dokumentobjekt in der Datenbank.
  ///
  /// [file] - RestApiUploadFile-Objekt mit Dateipfad oder Bytes
  /// [replaceOID] - OID eines bestehenden Dokuments zum Ersetzen
  /// [patch] - Patch-Modus verwenden (Standard: true)
  /// [fetchToObject] - Dokument-Objekt nach Upload erstellen (Standard: true)
  ///
  /// Returns: [RestApiResponse] mit Upload-Status und Dokument-ID
  ///
  /// Der Upload-Prozess erfolgt in drei Schritten:
  /// 1. Upload-ID vom Server anfordern
  /// 2. Datei mit Multipart-Request hochladen
  /// 3. Dokument-Objekt erstellen (falls fetchToObject=true)
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiUploadFile file = RestApiUploadFile.fromPath("/path/to/document.pdf");
  /// RestApiResponse response = await manager.uploadFile(
  ///   file,
  ///   fetchToObject: true
  /// );
  /// if (response.isOk) {
  ///   String documentId = response.data['objectId'];
  /// }
  /// ```
  Future<RestApiResponse> uploadFile(
    RestApiUploadFile file, {
    String replaceOID = "",
    bool patch = true,
    bool fetchToObject = true,
  }) async {
    try {
      RestApiResponse restApiResponse = await _getUploadID();

      String uploadID = jsonDecode(
        restApiResponse.httpResponse.body,
      )["data"]["uploadId"];

      await _postUploadFile(file, uploadID);

      if (!restApiResponse.isOk) {
        throw Exception("Can not upload file");
      }

      if (fetchToObject) {
        return await _patchUploadFile(uploadID, replaceOID);
      } else {
        return restApiResponse;
      }
    } catch (_) {
      rethrow;
    }
  }

  /// Lädt eine Datei mit Upload-Controller hoch
  ///
  /// Überträgt eine Datei asynchron auf den Server und erstellt einen Controller
  /// zur Überwachung des Upload-Fortschritts. Unterstützt sowohl lokale Dateien
  /// als auch Web-Uploads mit Fehlerbehandlung und Status-Callbacks.
  ///
  /// [file] - RestApiUploadFile-Objekt mit Dateipfad oder Bytes
  /// [replaceOID] - OID eines bestehenden Dokuments zum Ersetzen (optional)
  /// [patch] - Patch-Modus verwenden (Standard: true)
  /// [fetchToObject] - Dokument-Objekt nach Upload erstellen (Standard: true)
  ///
  /// Returns: [RestAPIFileUploadController] zur Überwachung des Upload-Status
  ///
  /// Der Upload-Prozess erfolgt in folgenden Schritten:
  /// 1. Upload-ID vom Server anfordern
  /// 2. Controller erstellen und zu aktiven Uploads hinzufügen
  /// 3. Asynchronen Upload mit Multipart-Request durchführen
  /// 4. Optional: Dokument-Objekt in der Datenbank erstellen
  /// 5. Controller mit Ergebnis oder Fehler abschließen
  ///
  /// Der Controller bietet:
  /// - Future für asynchrone Ergebnis-Behandlung
  /// - Automatische Fehlerbehandlung und -weiterleitung
  /// - Tracking aktiver Uploads zur Vermeidung von Duplikaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiUploadFile file = RestApiUploadFile.fromPath("/path/to/document.pdf");
  /// RestAPIFileUploadController controller = await manager.uploadFileWithController(
  ///   file,
  ///   fetchToObject: true
  /// );
  ///
  /// // Erfolgsfall behandeln
  /// controller.future.then((response) {
  ///   if (response.isOk) {
  ///     String documentId = response.data['objectId'];
  ///     print("Upload erfolgreich: $documentId");
  ///   }
  /// }).catchError((error) {
  ///   print("Upload fehlgeschlagen: $error");
  /// });
  /// ```
  Future<RestAPIFileUploadController> uploadFileWithController(
    RestApiUploadFile file, {
    String replaceOID = "",
    bool patch = true,
    bool fetchToObject = true,
    out,
  }) async {
    try {
      // Schritt 1: Upload-ID vom Server anfordern
      RestApiResponse restApiResponse = await _getUploadID();

      String uploadID = jsonDecode(
        restApiResponse.httpResponse.body,
      )["data"]["uploadId"];

      // Schritt 2: Controller erstellen und zu aktiven Uploads hinzufügen
      RestAPIFileUploadController controller = RestAPIFileUploadController(
        uploadID,
      );
      _activeUploads[uploadID] = controller;

      // Schritt 3: Asynchronen Upload-Prozess starten
      _postUploadFile(file, uploadID).then(
        (restApiResponse) async {
          // Upload aus aktiven Uploads entfernen
          _activeUploads.remove(uploadID);

          // Prüfung auf Upload-Fehler
          if (!restApiResponse.isOk) {
            controller.completeError(
              "${restApiResponse.internalStatus}: ${restApiResponse.statusMessage}",
            );
            return;
          }

          // Schritt 4: Optional - Dokument-Objekt in der Datenbank erstellen
          if (fetchToObject) {
            try {
              restApiResponse = await _patchUploadFile(uploadID, replaceOID);
            } catch (e) {
              controller.completeError(
                "${restApiResponse.internalStatus}: ${restApiResponse.statusMessage}",
              );
              return;
            }
          }

          // Schritt 5: Upload erfolgreich abgeschlossen
          controller.complete(restApiResponse);
        },
        onError: (error) {
          // Fehlerbehandlung: Upload aus aktiven Uploads entfernen
          _activeUploads.remove(uploadID);
          controller.completeError(error.toString());
        },
      );

      return controller;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> _postUploadFile(
    RestApiUploadFile file,
    String uploadID,
  ) async {
    String function = "v1/uploadFile";
    RestApiHttpMetric metric = RestApiHttpMetric(function, HttpMethod.post);

    try {
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$uploadID";
      Uri requestUri = _getUri(uriPath);

      Map<String, String> requestHeader = _getHeader(
        contentType: "application/x-www-form-urlencoded",
      );

      //Sending
      debugPrint("Uploadfile send: $requestUri");
      debugPrint("Request Header: $requestHeader");

      callbacks.triggerLogEvent("Uploadfile send: $requestUri");
      callbacks.triggerLogEvent("Request Header: $requestHeader");

      metric.start();

      var request = http.MultipartRequest('POST', requestUri);

      if (file.isPath && !kIsWeb) {
        request.files.add(
          await http.MultipartFile.fromPath(
            '',
            file.path!,
            filename: file.name,
          ),
        );
      } else {
        request.files.add(
          http.MultipartFile.fromBytes(
            "",
            file.bytes ?? [],
            filename: file.name,
          ),
        );
      }

      request.headers.addAll(requestHeader);

      http.StreamedResponse httpResponse = await request.send();

      http.Response response = await http.Response.fromStream(httpResponse);

      metric.responseCode = response.statusCode;
      metric.responsePayloadSize = response.contentLength;
      metric.responseContentType = response.headers['content-type'];
      metric.stop();

      return RestApiResponse(response);
    } catch (_) {
      rethrow;
    } finally {
      callbacks.triggerHttpMetricRecordedEvent(metric);
    }
  }

  /// Ruft Informationen über eine hochgeladene Datei ab, einschließlich Größe und MD5-Hash
  ///
  /// Diese Methode ruft Metadaten für eine Datei ab, die mit der angegebenen Upload-ID
  /// auf den Server hochgeladen wird. Die Antwort enthält die Dateigröße in Bytes
  /// und den MD5-Hash zur Verifikation.
  ///
  /// [uploadID] - Die eindeutige Kennung der hochgeladenen Datei
  ///
  /// Returns: [RestApiResponse] mit Datei-Metadaten und Größeninformationen
  ///
  /// Die Antwort enthält:
  /// - Dateigröße in Bytes
  /// - MD5-Hash zur Integritätsprüfung
  /// - Status-Informationen über den Upload
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse restApiResponse = await manager.getUploadFile("upload-123");
  /// if (restApiResponse.isOk) {
  ///   int fileSize = restApiResponse.httpResponse.body['data']['size'];
  ///   String md5Hash = restApiResponse.httpResponse.body['data']['hash'];
  ///   print("Dateigröße: $fileSize Bytes, Hash: $md5Hash");
  /// }
  /// ```
  Future<RestApiResponse> getUploadFile(String uploadID) async {
    try {
      String function = "v1/uploadFile";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$uploadID";

      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> _patchUploadFile(
    String uploadID,
    String replaceOID,
  ) async {
    try {
      String function = "v1/uploadFile";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$uploadID";
      Map<String, String> params = {};

      if (replaceOID.isNotEmpty) params['replaceOID'] = replaceOID;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> _getUploadID() async {
    try {
      String function = "v1/uploadFile";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Speichert Benutzereinstellungen auf dem Server
  ///
  /// Speichert benutzerspezifische Konfigurationsdaten unter einem Schlüssel.
  /// Ermöglicht die Persistierung von App-Einstellungen zwischen Sessions.
  ///
  /// [key] - Eindeutiger Schlüssel für die Einstellung
  /// [data] - Die zu speichernden Daten als Map
  ///
  /// Returns: [RestApiResponse] mit dem Speicherstatus
  ///
  /// Beispiel:
  /// ```dart
  /// Map<String, dynamic> settings = {
  ///   "theme": "dark",
  ///   "language": "de",
  ///   "notifications": true
  /// };
  /// RestApiResponse response = await manager.postUserSettings(
  ///   "app_preferences",
  ///   settings
  /// );
  /// ```
  Future<RestApiResponse> postUserSettings(
    String key,
    Map<String, dynamic> data,
  ) async {
    try {
      String function = "v1/userSetting";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$key";
      Uri requestUri = _getUri(uriPath);

      String requestBodyJson = jsonEncode(data);

      final response = RestApiResponse(
        await _http(
          HttpMethod.post,
          requestUri,
          function,
          body: requestBodyJson,
        ),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Markiert Dokumentannotationen als gelesen
  ///
  /// Setzt den Gelesen-Status für alle Annotationen eines Dokuments
  /// für den aktuellen Benutzer.
  ///
  /// [docOid] - OID oder UUID des Dokuments
  ///
  /// Returns: [RestApiResponse] mit dem Aktualisierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.docAnnotationsSetRead("doc-123");
  /// if (response.isOk) {
  ///   print("Annotationen als gelesen markiert");
  /// }
  /// ```
  Future<RestApiResponse> docAnnotationsSetRead(String docOid) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/execute/xDFAppDocumentAnnotationsSetRead";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['object'] = docOid;
      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft die Standard-E-Mail-Vorlage ab
  ///
  /// Lädt die systemweite Standard-E-Mail-Vorlage mit vorkonfigurierten
  /// Formatierungen und Platzhaltern.
  ///
  /// Returns: [RestApiResponse] mit der Standard-E-Mail-Vorlage
  ///
  /// Die Vorlage enthält:
  /// - HTML-Struktur für E-Mail-Layout
  /// - CSS-Styles für Formatierung
  /// - Platzhalter für dynamische Inhalte
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getDefaultEMailTemplate();
  /// if (response.isOk) {
  ///   String template = response.data['template'];
  /// }
  /// ```
  Future<RestApiResponse> getDefaultEMailTemplate() async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/execute/xDFAppGetDefaultEMailTemplate";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Konvertiert Klartext zu HTML für E-Mails
  ///
  /// Wandelt einfachen Textinhalt in HTML-formatierten Text um
  /// für die Verwendung in E-Mail-Nachrichten.
  ///
  /// [content] - Der zu konvertierende Klartext
  ///
  /// Returns: [RestApiResponse] mit dem HTML-formatierten Inhalt
  ///
  /// Automatische Konvertierungen:
  /// - Zeilenumbrüche zu <br>-Tags
  /// - URLs zu anklickbaren Links
  /// - E-Mail-Adressen zu mailto-Links
  ///
  /// Beispiel:
  /// ```dart
  /// String plaintext = "Hallo\nBesuchen Sie https://example.com";
  /// RestApiResponse response = await manager.convertEMailPlaintextToHTML(plaintext);
  /// if (response.isOk) {
  ///   String htmlContent = response.data['content'];
  /// }
  /// ```
  Future<RestApiResponse> convertEMailPlaintextToHTML(String content) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/execute/xDFAppConvertPlaintextToHTML";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap["content"] = content;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Konvertiert HTML zu Klartext für E-Mails
  ///
  /// Wandelt HTML-formatierten Text in einfachen Klartext um
  /// und entfernt alle HTML-Tags und Formatierungen.
  ///
  /// [content] - Der zu konvertierende HTML-Inhalt
  ///
  /// Returns: [RestApiResponse] mit dem Klartext-Inhalt
  ///
  /// Automatische Konvertierungen:
  /// - HTML-Tags werden entfernt
  /// - <br>-Tags werden zu Zeilenumbrüchen
  /// - Mehrfache Leerzeichen werden normalisiert
  /// - HTML-Entities werden dekodiert
  ///
  /// Beispiel:
  /// ```dart
  /// String htmlContent = "<p>Hallo<br/><a href='https://example.com'>Link</a></p>";
  /// RestApiResponse response = await manager.convertEMailHTMLToPlaintext(htmlContent);
  /// if (response.isOk) {
  ///   String plaintext = response.data['content'];
  /// }
  /// ```
  Future<RestApiResponse> convertEMailHTMLToPlaintext(String content) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/execute/xDFAppConvertHTMLToPlaintext";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap["content"] = content;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft E-Mail-Antwortdaten ab
  ///
  /// Lädt alle notwendigen Daten für die Erstellung einer E-Mail-Antwort
  /// inklusive ursprünglicher Nachricht, Empfänger und Formatierung.
  ///
  /// [emailOid] - OID oder UUID der ursprünglichen E-Mail
  ///
  /// Returns: [RestApiResponse] mit Antwortdaten und Metainformationen
  ///
  /// Die Antwortdaten enthalten:
  /// - Ursprüngliche E-Mail-Inhalte
  /// - Empfänger- und Absenderinformationen
  /// - Betreff mit "Re:"-Präfix
  /// - Formatierungsoptionen
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getEmailReplyData("email-123");
  /// if (response.isOk) {
  ///   Map<String, dynamic> replyData = response.data;
  ///   String originalSubject = replyData['subject'];
  /// }
  /// ```
  Future<RestApiResponse> getEmailReplyData(String emailOid) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/execute/xDFAppGetEMailReplyData";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap["email"] = emailOid;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Gibt Lizenzen für Anwendungen frei
  ///
  /// Gibt die Lizenzen für bestimmte Anwendungen in einer spezifizierten Session frei.
  /// Wird zur Lizenz-Verwaltung und zur Freigabe nicht mehr benötigter Lizenzen verwendet.
  ///
  /// [appnames] - Liste der Anwendungsnamen, für die Lizenzen freigegeben werden sollen
  /// [sessionId] - Session-ID für die Lizenz-Freigabe
  ///
  /// Returns: [RestApiResponse] mit dem Status der Lizenz-Freigabe
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.postLicenseRelease(
  ///   ["app1", "app2"],
  ///   "session-123"
  /// );
  /// if (response.isOk) {
  ///   print("Lizenzen erfolgreich freigegeben");
  /// }
  /// ```
  Future<RestApiResponse> postLicenseRelease(
    List<String> appnames,
    String sessionId,
  ) async {
    try {
      String function = "v1/license/release";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> requestHeader = _getHeader();
      Uri requestUri = _getUri(uriPath);
      Map<String, dynamic> requestBodyMap = {};
      String bodyText;

      requestBodyMap['appNames'] = appnames;
      bodyText = jsonEncode(requestBodyMap);

      requestHeader["sessionId"] = sessionId;

      final response = RestApiResponse(
        await _http(
          HttpMethod.post,
          requestUri,
          function,
          requestHeader: requestHeader,
          body: bodyText,
          handleSession: false,
        ),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Benutzer-Systemeinstellungen ab
  ///
  /// Lädt die systemweiten Einstellungen und Berechtigungen des aktuellen Benutzers.
  /// Enthält Informationen zu verfügbaren Funktionen und Benutzerrechten.
  ///
  /// [eventMacroName] - Name des Event-Makros für benutzerspezifische Anpassungen (optional)
  ///
  /// Returns: [RestApiUserSystemSettingsResponse] mit Benutzereinstellungen und Berechtigungen
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiUserSystemSettingsResponse response = await manager.getUserSystemSettings(eventMacroName: "myEvent");
  /// if (response.isOk) {
  ///   Map<String, dynamic> settings = response.settings;
  ///   bool canEditDocuments = response.hasPermission("edit_documents");
  /// }
  /// ```
  Future<RestApiUserSystemSettingsResponse> getUserSystemSettings({
    String eventMacroName = "",
  }) async {
    try {
      String function = "v1/userSystemSettings";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      if (eventMacroName.isNotEmpty) params['eventMacroName'] = eventMacroName;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiUserSystemSettingsResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Versionsinformationen des Servers ab
  ///
  /// Lädt detaillierte Informationen über die Server-Version, installierte Module
  /// und verfügbare Features der API.
  ///
  /// Returns: [RestApiVersionInfoResponse] mit Server-Versionsdaten und Modul-Informationen
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiVersionInfoResponse response = await manager.getVersionInfo();
  /// if (response.isOk) {
  ///   String serverVersion = response.version;
  ///   List<RestApiModule> modules = response.modules;
  ///   print("Server-Version: $serverVersion");
  /// }
  /// ```
  Future<RestApiVersionInfoResponse> getVersionInfo() async {
    try {
      String function = "v1/versioninfo";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiVersionInfoResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Startet die Zeiterfassung (Einstempeln) für einen Mitarbeiter
  ///
  /// Registriert den Arbeitsbeginn für die Personalzeiterfassung (PZE).
  /// Kann mit optionalem Schlüssel für verschiedene Tätigkeitsarten verwendet werden.
  ///
  /// [employeeoid] - OID des Mitarbeiters (optional, Standard: aktueller Benutzer)
  /// [key] - Tätigkeitsschlüssel für verschiedene Arbeitsarten (optional)
  ///
  /// Returns: [RestApiResponse] mit dem Status der Zeiterfassung
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.postPZEClockIn(
  ///   employeeoid: "emp-12345",
  ///   key: "PROJEKT_A"
  /// );
  /// if (response.isOk) {
  ///   print("Zeiterfassung gestartet");
  /// }
  /// ```
  Future<RestApiResponse> postPZEClockIn({
    String? employeeoid,
    String? key,
  }) async {
    try {
      String function = "v1/pze/clockIn";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, dynamic> bodyMap = {};
      String body;

      if (employeeoid != null) bodyMap['employeeoid'] = employeeoid;
      if (key != null) bodyMap['key'] = key;

      body = json.encode(bodyMap);

      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Beendet die Zeiterfassung (Ausstempeln) für einen Mitarbeiter
  ///
  /// Registriert das Arbeitsende für die Personalzeiterfassung (PZE).
  /// Berechnet automatisch die Arbeitszeit seit dem letzten Einstempeln.
  ///
  /// [employeeoid] - OID des Mitarbeiters (optional, Standard: aktueller Benutzer)
  ///
  /// Returns: [RestApiResponse] mit den erfassten Arbeitszeiten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.postPZEClockOut(
  ///   employeeoid: "emp-12345"
  /// );
  /// if (response.isOk) {
  ///   print("Zeiterfassung beendet");
  ///   // Arbeitszeit wird automatisch berechnet
  /// }
  /// ```
  Future<RestApiResponse> postPZEClockOut({String? employeeoid}) async {
    try {
      String function = "v1/pze/clockOut";
      Map<String, String> params = {};
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";

      if (employeeoid != null) params['employeeoid'] = employeeoid;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft verfügbare Arbeitszeitschlüssel für die PZE ab
  ///
  /// Lädt alle verfügbaren Tätigkeitsschlüssel und Arbeitszeitkategorien
  /// für die Personalzeiterfassung.
  ///
  /// [serialization] - Serialisierungsoptionen für die Ausgabe
  ///
  /// Returns: [RestApiResponse] mit der Liste verfügbarer Zeitschlüssel
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getPZEWorkingTimeKeys();
  /// if (response.isOk) {
  ///   List keys = response.data['workingTimeKeys'];
  ///   // keys enthält: [{"key": "PROJEKT_A", "name": "Projekt A"}, ...]
  /// }
  /// ```
  Future<RestApiResponse> getPZEWorkingTimeKeys({
    String serialization = "",
  }) async {
    try {
      String function = "v1/pze/workingTimeKeys";
      Map<String, String> params = {};
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";

      if (serialization.isNotEmpty) params['serialization'] = serialization;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Arbeitszeitkonten für einen Zeitraum ab
  ///
  /// Lädt die Arbeitszeiterfassung und Stundensalden für einen bestimmten
  /// Mitarbeiter und Zeitraum aus der PZE.
  ///
  /// [serialization] - Serialisierungsoptionen für die Ausgabe
  /// [employeeOid] - OID des Mitarbeiters (optional, Standard: aktueller Benutzer)
  /// [from] - Startzeitpunkt für den Abfragezeitraum
  /// [to] - Endzeitpunkt für den Abfragezeitraum
  ///
  /// Returns: [RestApiResponse] mit Arbeitszeitdaten und Salden
  ///
  /// Beispiel:
  /// ```dart
  /// DateTime start = DateTime.now().subtract(Duration(days: 30));
  /// DateTime end = DateTime.now();
  /// RestApiResponse response = await manager.getPZEWorkingTimeAccounts(
  ///   employeeOid: "emp-12345",
  ///   from: start,
  ///   to: end
  /// );
  /// ```
  Future<RestApiResponse> getPZEWorkingTimeAccounts({
    String serialization = "",
    String? employeeOid,
    DateTime? from,
    DateTime? to,
  }) async {
    try {
      String function = "v1/pze/workingTimeAccounts";
      Map<String, String> params = {};
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";

      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (employeeOid != null) params['employeeOid'] = employeeOid;
      if (from != null) params['from'] = from.toISOFormatString();
      if (to != null) params['to'] = to.toISOFormatString();

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Benutzer-Zuordnungen und Rollen ab
  ///
  /// Lädt alle Zuordnungen des aktuellen Benutzers zu Gruppen, Rollen
  /// und Berechtigungen im System.
  ///
  /// Returns: [RestApiResponse] mit Benutzer-Zuordnungsdaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getUserAssignments();
  /// if (response.isOk) {
  ///   List assignments = response.data['assignments'];
  ///   // assignments enthält Gruppen und Rollen
  /// }
  /// ```
  Future<RestApiResponse> getUserAssignments() async {
    try {
      String function = "v1/execute/xDFAppGetUserAssignments";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft den öffentlichen Schlüssel für sichere v2-Anmeldung ab
  ///
  /// Lädt den RSA-Public-Key vom Server für die verschlüsselte Anmeldung
  /// über den v2/login/secure Endpunkt.
  ///
  /// Returns: [RestApiLoginSecureKeyResponse] mit dem öffentlichen RSA-Schlüssel
  ///
  /// Diese Methode wird intern von der login()-Methode verwendet,
  /// wenn v2Login auf false gesetzt ist.
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiLoginSecureKeyResponse response = await manager.getLoginSecureKey();
  /// if (response.isOk) {
  ///   String publicKey = response.key;
  ///   // Verwende publicKey für RSA-Verschlüsselung
  /// }
  /// ```
  Future<RestApiLoginSecureKeyResponse> getLoginSecureKey() async {
    try {
      String function = "v2/login/secure/key";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> requestHeader = _getHeader(addSessionId: false);
      Uri requestUri = _getUri(uriPath);

      final response = RestApiLoginSecureKeyResponse(
        await _http(
          HttpMethod.get,
          requestUri,
          function,
          requestHeader: requestHeader,
          handleSession: false,
        ),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft den öffentlichen Schlüssel für v2-Anmeldung ab
  ///
  /// Lädt den RSA-Public-Key vom Server für die verschlüsselte Anmeldung
  /// über den v2/login Endpunkt mit AES-Verschlüsselung.
  ///
  /// Returns: [RestApiLoginSecureKeyResponse] mit dem öffentlichen RSA-Schlüssel
  ///
  /// Diese Methode wird intern von der login()-Methode verwendet,
  /// wenn v2Login auf true gesetzt ist (Standard).
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiLoginSecureKeyResponse response = await manager.getLoginKey();
  /// if (response.isOk) {
  ///   String publicKey = response.key;
  ///   // Verwende publicKey für AES-verschlüsselte Anmeldung
  /// }
  /// ```
  Future<RestApiLoginSecureKeyResponse> getLoginKey() async {
    try {
      String function = "v2/login/key";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> requestHeader = _getHeader(addSessionId: false);
      Uri requestUri = _getUri(uriPath);

      final response = RestApiLoginSecureKeyResponse(
        await _http(
          HttpMethod.get,
          requestUri,
          function,
          requestHeader: requestHeader,
          handleSession: false,
        ),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Erstellt den verschlüsselten Request-Body für v2/login
  ///
  /// Private Methode zur Erstellung des AES-verschlüsselten Anmeldekörpers
  /// für den Standard v2-Login. Kombiniert AES- und RSA-Verschlüsselung
  /// für optimale Performance und Sicherheit.
  ///
  /// [clearBody] - Der unverschlüsselte JSON-String mit Anmeldedaten
  /// [serverPublicKeyString] - Der öffentliche RSA-Schlüssel des Servers
  ///
  /// Returns: JSON-String mit AES-verschlüsselten Daten und RSA-verschlüsseltem AES-Key
  ///
  /// Der Prozess umfasst:
  /// 1. AES-Schlüssel generieren
  /// 2. Anmeldedaten mit AES verschlüsseln
  /// 3. AES-Schlüssel mit Server-RSA-Key verschlüsseln
  /// 4. Client-RSA-Public-Key für Antwort-Entschlüsselung bereitstellen
  Future<String> _getv2LoginBody(
    String clearBody,
    String serverPublicKeyString,
  ) async {
    // Öffnen des öffentlichen Schlüssels
    final publicKey = serverPublicKeyString.parsePublicKeyFromPem();

    await EncryptionManager().initializeRSAKeyPair();
    await EncryptionManager().initializeAESKey();

    Map<String, dynamic> encryptedBodyJson = jsonDecode(
      await EncryptionManager().encryptAES(clearBody, padding: "PKCS7"),
    );

    Uint8List encryptedBodyIv = base64Decode(encryptedBodyJson["iv"] ?? "");
    Uint8List encryptedBodyData = base64Decode(encryptedBodyJson["data"] ?? "");

    Uint8List encryptedBodyMerged = Uint8List(
      encryptedBodyIv.length + encryptedBodyData.length,
    );
    encryptedBodyMerged.setRange(0, encryptedBodyIv.length, encryptedBodyIv);
    encryptedBodyMerged.setRange(
      encryptedBodyIv.length,
      encryptedBodyMerged.length,
      encryptedBodyData,
    );

    // Daten verschlüsseln
    final encryptedBodyBase64 = base64.encode(encryptedBodyMerged);

    final encryptedAesKeyBase64 = base64.encode(
      await EncryptionManager().encryptRSA(
        EncryptionManager().keyAES!.bytes,
        publicKey: publicKey,
      ),
    );

    // Der öffentliche Schlüssel im PEM-Format, ebenfalls base64-kodiert
    final publicKeyBase64 = EncryptionManager().keyRSA!.publicKey.encodeToPem();

    // Anfragenkörper erstellen
    Map<String, dynamic> requestBody = {
      "aesKey": encryptedAesKeyBase64,
      "data": encryptedBodyBase64,
      "publicKey": publicKeyBase64,
    };

    return jsonEncode(requestBody);
  }

  /// Ruft Dokumentpfade für ein Objekt ab
  ///
  /// Lädt die Pfad-Informationen und Speicherort-Details für ein
  /// spezifisches Dokument oder Objekt.
  ///
  /// [oid] - Die Objekt-ID des Dokuments
  ///
  /// Returns: [RestApiResponse] mit Pfad-Informationen und Metadaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.getDocumentPaths("doc-12345");
  /// if (response.isOk) {
  ///   Map paths = response.data;
  ///   String physicalPath = paths['physicalPath'];
  ///   String virtualPath = paths['virtualPath'];
  /// }
  /// ```
  Future<RestApiResponse> getDocumentPaths(String oid) async {
    try {
      String function = "v1/docs/documentPaths";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$oid";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Validiert ein 2FA-Token für eine Anwendung
  ///
  /// Überprüft, ob das angegebene 2FA-Token (TOTP) für die spezifizierte
  /// Anwendung gültig ist. Wird zur Verifikation von Zwei-Faktor-Authentifizierung verwendet.
  ///
  /// [appname] - Name der Anwendung (z.B. "GSD-DFApp")
  /// [token] - Das 6-stellige 2FA-Token vom Authenticator
  ///
  /// Returns: [RestApiResponse] mit dem Validierungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.validate2FASecret(
  ///   "GSD-DFApp",
  ///   "123456"
  /// );
  /// if (response.isOk) {
  ///   print("2FA-Token ist gültig");
  /// }
  /// ```
  Future<RestApiResponse> validate2FASecret(
    String appname,
    String token,
  ) async {
    try {
      String function = "v1/2fa/validate";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      params['app'] = appname;

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['token'] = token;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft 2FA-Secret-Informationen für einen Benutzer ab
  ///
  /// Lädt die 2FA-Konfigurationsdaten für einen spezifischen Benutzer
  /// und eine Anwendung, einschließlich Aktivierungs- und Bestätigungsstatus.
  ///
  /// [appname] - Name der Anwendung (z.B. "GSD-DFApp")
  /// [username] - Benutzername für die 2FA-Abfrage
  ///
  /// Returns: [RestApi2FASecretResponse] mit 2FA-Status und Konfigurationsdaten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApi2FASecretResponse response = await manager.get2FASecret(
  ///   "GSD-DFApp",
  ///   "mueller"
  /// );
  /// if (response.isOk) {
  ///   bool isActivated = response.isActivated;
  ///   bool isConfirmed = response.isConfirmed;
  ///   int status = response.twoFaStatus;
  /// }
  /// ```
  Future<RestApi2FASecretResponse> get2FASecret(
    String appname,
    String username,
  ) async {
    try {
      String function = "v1/2fa/secret";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      params['app'] = appname;
      params['username'] = username;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApi2FASecretResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Erstellt ein neues 2FA-Secret für eine Anwendung
  ///
  /// Generiert ein neues TOTP-Secret für die Zwei-Faktor-Authentifizierung
  /// einer spezifischen Anwendung. Das Secret wird für die Einrichtung
  /// von Authenticator-Apps verwendet.
  ///
  /// [appname] - Name der Anwendung (z.B. "GSD-DFApp")
  ///
  /// Returns: [RestApiResponse] mit dem neuen 2FA-Secret und QR-Code-Daten
  ///
  /// Das Response enthält:
  /// - Base32-kodiertes Secret für manuelle Eingabe
  /// - QR-Code-URL für Authenticator-Apps
  /// - Backup-Codes für Notfälle
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.create2FASecret("GSD-DFApp");
  /// if (response.isOk) {
  ///   String secret = response.data['secret'];
  ///   String qrCodeUrl = response.data['qrCode'];
  ///   List backupCodes = response.data['backupCodes'];
  /// }
  /// ```
  Future<RestApiResponse> create2FASecret(String appname) async {
    try {
      String function = "v1/2fa/secret";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};

      params['app'] = appname;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Erneuert ein bestehendes 2FA-Secret
  ///
  /// Generiert ein neues TOTP-Secret für eine bereits konfigurierte
  /// 2FA-Anwendung. Erfordert ein gültiges Token zur Autorisierung.
  ///
  /// [appname] - Name der Anwendung (z.B. "GSD-DFApp")
  /// [token] - Gültiges 2FA-Token zur Autorisierung der Erneuerung
  ///
  /// Returns: [RestApiResponse] mit dem neuen 2FA-Secret und Konfigurationsdaten
  ///
  /// Nach der Erneuerung:
  /// - Das alte Secret wird ungültig
  /// - Ein neues Secret wird generiert
  /// - Authenticator-Apps müssen neu konfiguriert werden
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.refresh2FASecret(
  ///   "GSD-DFApp",
  ///   "123456"
  /// );
  /// if (response.isOk) {
  ///   String newSecret = response.data['secret'];
  ///   // Benutzer muss Authenticator-App neu einrichten
  /// }
  /// ```
  Future<RestApiResponse> refresh2FASecret(String appname, String token) async {
    try {
      String function = "v1/2fa/secret";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      params['app'] = appname;

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['token'] = token;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.patch, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Löscht ein 2FA-Secret für eine Anwendung
  ///
  /// Entfernt die 2FA-Konfiguration für eine spezifische Anwendung
  /// und deaktiviert die Zwei-Faktor-Authentifizierung.
  ///
  /// [appname] - Name der Anwendung (z.B. "GSD-DFApp")
  /// [token] - Gültiges 2FA-Token zur Autorisierung der Löschung
  ///
  /// Returns: [RestApiResponse] mit dem Löschstatus
  ///
  /// Nach der Löschung:
  /// - 2FA wird für die Anwendung deaktiviert
  /// - Alle Backup-Codes werden ungültig
  /// - Normale Passwort-Anmeldung ist wieder möglich
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await manager.delete2FASecret(
  ///   "GSD-DFApp",
  ///   "123456"
  /// );
  /// if (response.isOk) {
  ///   print("2FA erfolgreich deaktiviert");
  /// }
  /// ```
  Future<RestApiResponse> delete2FASecret(String appname, String token) async {
    try {
      String function = "v1/2fa/secret";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, String> params = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      params['app'] = appname;

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['token'] = token;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.delete, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Setzt die Objekt-Sicherheitseinstellungen für ein Dokument/Objekt
  ///
  /// Definiert oder aktualisiert die Zugriffsrechte für bestimmte Benutzer
  /// auf ein spezifisches Objekt im System. Jeder Benutzer erhält
  /// individuelle Rechte-Flags, die die erlaubten Aktionen bestimmen.
  ///
  /// [oid] - Die eindeutige Objekt-ID des zu konfigurierenden Elements
  /// [userObjectSecurity] - Map mit Benutzername als Key und Rechte-Flags als Value
  /// [replace] - Ob bestehende Rechte ersetzt werden sollen (Standard: false)
  ///
  /// Returns: [RestApiResponse] mit dem Status der Sicherheitskonfiguration
  ///
  /// **Map-Format:**
  /// ```json
  /// {
  ///   "userObjectName": "test1",
  ///   "rights": 7
  /// }
  /// ```
  ///
  /// Beispiel:
  /// ```dart
  /// Map<String, int> security = {
  ///   "user1": 7,
  ///   "user2": 15,
  /// };
  /// RestApiResponse response = await manager.setObjectSecurity(
  ///   "A12BC",
  ///   security,
  ///   replace: true
  /// );
  /// ```
  Future<RestApiResponse> setObjectSecurity(
    String oid,
    Map<String, int> userObjectSecurity, {
    bool replace = false,
  }) async {
    try {
      String function = "v1/setObjectSecurity";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function/$oid";
      Map<String, dynamic> bodyMap = {};
      String body;

      List<dynamic> items = [];

      userObjectSecurity.forEach((key, value) {
        items.add({"userObjectName": key, "rights": value});
      });

      Uri requestUri = _getUri(uriPath);

      bodyMap['security'] = items;
      if (replace) bodyMap['replace'] = replace;

      body = json.encode(bodyMap);

      final response = RestApiResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Führt eine benutzerdefinierte HTTP-Anfrage aus
  ///
  /// Ermöglicht die Ausführung beliebiger HTTP-Anfragen mit vollständiger
  /// Kontrolle über Methode, URI, Header und Body. Ideal für spezielle
  /// API-Aufrufe, die nicht durch die Standard-Methoden abgedeckt sind.
  ///
  /// [method] - Die HTTP-Methode (GET, POST, PUT, DELETE, etc.)
  /// [uriPath] - Der URI-Pfad für die Anfrage
  /// [requestHeader] - Optionale zusätzliche HTTP-Header
  /// [params] - Optionale Query-Parameter für die URL
  /// [body] - Optionaler Request-Body (JSON, XML, etc.)
  /// [handleSession] - Session-Handling aktivieren (Standard: true)
  ///
  /// Returns: RestApiResponse mit der Server-Antwort
  ///
  /// Throws: HttpRequestException bei HTTP-Fehlern
  /// Throws: SessionInvalidException bei ungültiger Session
  Future<RestApiResponse> customRequest(
    HttpMethod method,
    String uriPath, {
    Map<String, String>? requestHeader,
    Map<String, String>? params,
    String? body,
    bool handleSession = true,
  }) async {
    try {
      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(
        await _http(
          method,
          requestUri,
          uriPath,
          requestHeader: requestHeader,
          body: body,
          handleSession: handleSession,
        ),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Synchronisations-Klassen-Informationen für eine Anwendung ab
  ///
  /// Diese Methode lädt die verfügbaren Synchronisations-Klassen und deren
  /// Metadaten für eine spezifische Anwendung. Die Informationen enthalten
  /// Details über synchronisierbare Datenstrukturen und deren Eigenschaften.
  ///
  /// [appName] - Name der Anwendung, für die Klassen-Info abgerufen werden soll
  ///
  /// Returns: RestApiResponse mit den Klassen-Informationen als JSON
  ///
  /// Throws: HttpRequestException bei HTTP-Fehlern
  /// Throws: SessionInvalidException bei ungültiger Session
  Future<RestApiResponse> getSyncClassInfo(String appName) async {
    try {
      String function = "/v1/xSync/ClassInfo/$appName";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";

      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(
        await _http(HttpMethod.get, requestUri, function),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Ruft Synchronisations-Objekte einer spezifischen Klasse ab
  ///
  /// Diese Methode lädt alle verfügbaren Objekte einer bestimmten
  /// Synchronisations-Klasse für eine Anwendung. Die Objekte enthalten
  /// die aktuellen Daten und Metadaten für die Synchronisation.
  ///
  /// [appName] - Name der Anwendung
  /// [className] - Name der Klasse, deren Objekte abgerufen werden sollen
  ///
  /// Returns: RestApiResponse mit den Objektdaten als JSON
  ///
  /// Throws: HttpRequestException bei HTTP-Fehlern
  /// Throws: SessionInvalidException bei ungültiger Session
  Future<RestApiSyncClassResponse> getSyncObjectsOfClass(
    String appName,
    String className, {
    List<RestApiSyncContainer> nextContainers = const [],
    int? maxRecords,
  }) async {
    try {
      String function = "/v1/xSync/dynamic/$appName/$className";
      String uriPath =
          "${_config.alias.isEmpty ? "" : "/${_config.alias}"}/$function";
      Map<String, dynamic> bodyMap = {};
      String? body;

      if (maxRecords != null) {
        bodyMap['maxRecords'] = maxRecords;
      }

      if (nextContainers.isNotEmpty) {
        for (var container in nextContainers) {
          bodyMap[container.containerId] = {
            "lastMarker": container.nextMarker,
            "revision": container.revision,
          };
        }
      }

      body = bodyMap.isNotEmpty ? json.encode(bodyMap) : null;

      Uri requestUri = _getUri(uriPath);

      final response = RestApiSyncClassResponse(
        await _http(HttpMethod.post, requestUri, function, body: body),
      );
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Räumt alle Ressourcen auf
  ///
  /// Sollte aufgerufen werden, wenn der RestApiManager nicht mehr benötigt wird.
  /// Schließt den HTTP-Client und räumt Timer auf.
  void dispose() {
    _bufferFlushTimer?.cancel();
    _client.close();
  }
}
