import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:collection/collection.dart';
import 'package:encryption/encryptionmanager.dart';
import 'package:encryption/extension.dart';
import 'package:event/event.dart';
import 'package:file_picker/file_picker.dart';
import 'package:firebase_performance/firebase_performance.dart' as firebase_performance;
import 'package:firebase_performance/firebase_performance.dart';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:http/http.dart';
import 'package:iso8601_duration/iso8601_duration.dart';
import 'package:encrypt/encrypt.dart' as encrpyt;
import 'package:pointycastle/export.dart';
import 'package:restapi/exception/licenseexception.dart';
import 'package:restapi/exception/sessioninvalidexception.dart';
import 'package:restapi/exception/tokenorsessionismissingexception.dart';
import 'package:restapi/exception/userandpasswrongexception.dart';
import 'package:restapi/extension.dart';
import 'package:restapi/httpclient/httpclient.dart';
import 'package:restapi/responses/refreshsessionresponse.dart';
import 'package:restapi/responses/restapicheckserviceresponse.dart';
import 'package:restapi/responses/restapifileresponse.dart';
import 'package:restapi/responses/restapiloginresponse.dart';
import 'package:restapi/responses/restapiloginsecurekeyresponse.dart';
import 'package:restapi/responses/restapiobjectlockresponse.dart';
import 'package:restapi/responses/restapiresponse.dart';
import 'package:restapi/responses/restapiusersystemsettingsresponse.dart';
import 'package:restapi/responses/restapiversioninforesponse.dart';
import 'package:restapi/restapidevice.dart';
import 'package:restapi/restapifoldertype.dart';
import 'package:restapi/restapirequest.dart';

enum HttpMethod { get, post, put, patch, delete }

/// Manager for all rest-api related data and functions
class RestApiManager {
  final Duration _connectionTimeout = const Duration(seconds: 5);
  final Duration _reponseTimeout = const Duration(minutes: 10);

  get serverUrl => _serverUrl;
  get alias => _alias;
  get sessionId => _sessionId;
  get pendingResponses => _pendingResponses;
  get loggedIn => _loggedIn;
  get allowSslError => _allowSslError;
  get perPageCount => _perPageCount;

  RestApiDevice? device;

  /// AppKey for example ```GSD-DFApp```.
  final String _appKey;

  /// Alias of the database for example ```dfapp```
  ///
  /// Needed for some functions like ```fileupload``` and incase the webservice is connected to multiple databases
  final String _alias;

  /// Username for example ```GSDAdmin```.
  final String _userName;

  /// Password as MD5 hash for example ```098f6bcd4621d373cade4e832627b4f6``` for the password ```test```.
  String _password = "";

  /// AppNames for example ```GSD-RestApi```. For multiple app names use ',' to seperate them like  ```GSD-RestApi,GSD-DFApp```.
  List<String> appNames;
  List<String> additionalAppNames = [];

  /// Server-URL includes the protocol ```http/https``` the ip ```127.0.0.1``` and the port ```8080```
  ///
  /// The value should look like this  ```https:127.0.0.1:8080```.
  final String _serverUrl;

  Uri _baseUri = Uri();

  /// Session id that is returned by the login function.
  String _sessionId = "";
  int _perPageCount = 0;
  final Map<String, RestApiRequest> _pendingResponses = {};
  bool v2Login = true;
  bool _loggedIn = false;
  bool _allowSslError = false;
  bool _manualLoggedOut = false;

  Event sessionIdChangedEvent = Event();
  Event userAndPassWrongEvent = Event();
  Event licenseWrongEvent = Event();
  FirebasePerformance? performance;

  /// Creates a [RestApiManger] object
  RestApiManager(this._appKey, this._userName, this.appNames, this._serverUrl, this._alias,
      {this.device, int perPageCount = 50, String sessionid = "", bool allowSslError = false, FirebasePerformance? firebasePerformance}) {
    _perPageCount = perPageCount;
    _sessionId = sessionid;
    _allowSslError = allowSslError;
    performance = firebasePerformance;

    _baseUri = Uri.parse(serverUrl);
  }

  void setPassword(String password) {
    _password = password;
  }

  Map<String, String> _getHeader({String contentType = "application/json", bool addAppKey = true, bool addSessionId = true}) {
    Map<String, String> header = {};
    if (contentType.isNotEmpty) header['Content-type'] = contentType;
    if (addAppKey) header['appkey'] = _appKey;
    if (addSessionId) header['sessionid'] = sessionId;

    return header;
  }

  Uri _getUri(String path, {Map<String, String>? params}) {
    String pathCombined;

    pathCombined = "${_baseUri.path}$path";
    Uri uri = _baseUri.replace(path: pathCombined, queryParameters: params);

    return uri;
  }

  Future<Response> _http(HttpMethod method, Uri requestUri, String function,
      {String? body,
      Map<String, String>? requestHeader,
      bool handleSession = true,
      bool useRequestHeader = true,
      bool decryptRSA = false,
      bool decryptAES = false,
      bool login = false}) async {
    Response httpResponse;
    bool repeat = false;

    do {
      if (useRequestHeader) {
        requestHeader ??= _getHeader();
      }

      if(kDebugMode) {
        debugPrint("RequestUri send: $requestUri");
        debugPrint("Request Header: $requestHeader");
        debugPrint("Request Body: ${(body?.length ?? 0 ) > 1000 ? "${body?.substring(0, 1000)}..." : body}"); // dont trace full email content = performance issue
      }

      httpResponse = await _performRequest(
          requestUri: requestUri,
          requestHeader: requestHeader,
          body: body,
          method: method,
          connectionTimeout: _connectionTimeout,
          responseTimeout: _reponseTimeout,
          function: function, 
          login: login);

      if (!httpResponse.body.isValidJson()) {
        String decodedResponseBody = "";

        if (decryptRSA) {
          decodedResponseBody = await EncryptionManager().decryptRSAInBlocks(httpResponse.body);
        }

        if (decryptAES) {
          List<String> responseBodyParts = httpResponse.body.split("|");

          String aesKeyPart = responseBodyParts[0];
          String bodyPart = responseBodyParts[1];

          String aesKeyString = base64Encode(await EncryptionManager().decryptRSA(base64Decode(aesKeyPart)));

          encrpyt.Key aesKey = encrpyt.Key.fromBase64(aesKeyString);

          Uint8List bodyPartBytes = base64Decode(bodyPart);

          Map<String, dynamic> aesJson = {
            "iv": base64Encode(bodyPartBytes.sublist(0, 16)),
            "data": base64Encode(bodyPartBytes.sublist(16, bodyPartBytes.length))
          };

          decodedResponseBody = await EncryptionManager().decryptAES(jsonEncode(aesJson), key: aesKey, padding: "PKCS7");
        }

        httpResponse = http.Response(decodedResponseBody, httpResponse.statusCode, headers: httpResponse.headers);
      }

      if (useRequestHeader && requestHeader != null) {
        try {
          RestApiResponse(httpResponse);
          repeat = false;
        } on SessionInvalidException {
          if (handleSession && _loggedIn && !_manualLoggedOut) {
            RefreshSessionResponse response = await _refreshSession();
            if (response.isActive) {
              repeat = true;
              requestHeader['sessionid'] = response.sessionId;
            }
          }
        } on TokenOrSessionIsMissingException {
          if (handleSession && _loggedIn && !_manualLoggedOut) {
            RefreshSessionResponse response = await _refreshSession();
            if (response.isActive) {
              repeat = true;
              requestHeader['sessionid'] = response.sessionId;
            }
          }
        } on UserAndPassWrongException {
          userAndPassWrongEvent.broadcast();
          rethrow;
        } on LicenseException {
          licenseWrongEvent.broadcast();
          rethrow;
        } catch (e) {
          rethrow;
        }
      }
    } while (repeat);

    _loggedIn = true;

    return (httpResponse);
  }

  Future<http.Response> _performRequest(
      {required Uri requestUri,
      required Map<String, String>? requestHeader,
      required dynamic body,
      required HttpMethod method,
      required Duration connectionTimeout,
      required Duration responseTimeout,
      required String function,
      bool login = false}) async {
    final String requestHash = '$requestUri|${requestHeader.toString()}|${body.toString()}'.toMd5Hash();

    if (_pendingResponses.containsKey(requestHash)) {
      return await _pendingResponses[requestHash]!.response;
    }

    if(login) {
      RestApiRequest? request = _pendingResponses.values.firstWhereOrNull((element) => element.login);

      if(request != null) {
        return await request.response;
      }
    }

    // Plattformabhängige Auswahl des richtigen HTTP-Clients:
    final http.Client client = createClient(_connectionTimeout, allowSslError: _allowSslError);

    Future<http.Response> requestFunction = Future<http.Response>(() async {
      try {
        final request = http.Request(method.name.toUpperCase(), requestUri);
        if (requestHeader != null) {
          request.headers.addAll(requestHeader);
        }
        if (body != null) {
          request.body = body;
        }

        // Sende die Anfrage – der connectionTimeout wird hier vom HttpClient berücksichtigt
        final http.StreamedResponse streamedResponse = await client.send(request);

        HttpMetric? metric = !kIsWeb
            ? performance?.newHttpMetric("https://gsd-software.com/$function", firebase_performance.HttpMethod.Post)
            : null;
        await metric?.start();

        // Verarbeite die Antwort mit einem separaten Response Timeout
        final http.Response response = await http.Response.fromStream(streamedResponse).timeout(
          responseTimeout,
        );

        metric?.httpResponseCode = response.statusCode;
        metric?.responsePayloadSize = response.contentLength;
        metric?.responseContentType = response.headers['content-type'];
        await metric?.stop();

        return response;
      } catch (e) {
        _pendingResponses.remove(requestHash);
        rethrow;
      } finally {
        _pendingResponses.remove(requestHash);
        client.close();
      }
    });

    _pendingResponses[requestHash] = RestApiRequest(requestFunction, login: login);

    return await _pendingResponses[requestHash]!.response;
  }

  /// Logs the user in to the database via '/v1/login'
  ///
  /// Throws exceptions defined in [RestApiResponse] and [RestApiLoginResponse]
  Future<RestApiLoginResponse> login(String md5Password) async {
    try {
      String v2LoginSecurefunction = "v2/login/secure";
      String v2Loginfunction = "v2/login";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/${v2Login ? v2Loginfunction : v2LoginSecurefunction}";
      Uri requestUri = _getUri(uriPath);

      Map<String, String> requestHeader = _getHeader(addSessionId: false);
      Map<String, dynamic> requestBodyMap = {};
      Map<String, dynamic> deviceMap = {};
      String bodyText;

      List<String> completeAppnames = [];
      completeAppnames.addAll(appNames);
      completeAppnames.addAll(additionalAppNames);

      requestBodyMap['user'] = _userName;
      requestBodyMap['pass'] = md5Password;
      requestBodyMap['appNames'] = completeAppnames;
      if (device != null) {
        deviceMap = device!.toJson();
        requestBodyMap['device'] = deviceMap;
      }
      requestBodyMap['furtherencryption'] = false;

      RestApiLoginSecureKeyResponse secureKeyResponse;

      if(v2Login) {
        secureKeyResponse = await getLoginKey();
      } else {
        secureKeyResponse = await getLoginSecureKey();
      }

      if (!secureKeyResponse.isOk) {
        throw Exception("Secure Key can not be provided");
      }

      String serverPublicKey = secureKeyResponse.key;

      if(v2Login) {
        bodyText = await _getv2LoginBody(jsonEncode(requestBodyMap), serverPublicKey);
      } else {
        bodyText = await _getv2LoginSecureBody(jsonEncode(requestBodyMap), serverPublicKey);
      }

      final response = RestApiLoginResponse(await _http(HttpMethod.post, requestUri, v2Login ? v2Loginfunction : v2LoginSecurefunction,
          handleSession: false, body: bodyText, requestHeader: requestHeader, decryptRSA: !v2Login, decryptAES: v2Login, login: true));

      if (response.isOk) {
        _password = md5Password;
        _sessionId = response.sessionId;
        _loggedIn = true;
        _manualLoggedOut = false;
        sessionIdChangedEvent.broadcast();
      }
      return (response);
    } catch (e) {
      _sessionId = "";
      sessionIdChangedEvent.broadcast();
      rethrow;
    }
  }

  /// Checks the session via ```/_CheckSession```
  ///
  /// Throws exceptions defined in [RestApiResponse]
  Future<RestApiResponse> checkSession() async {
    try {
      String function = "_CheckSession";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// Checks the session via ```/CheckService```
  static Future<RestApiCheckServiceResponse> checkServiceWithUri(Uri requestUri) async {
    try {
      final response = RestApiCheckServiceResponse(await http.get(requestUri).timeout(const Duration(seconds: 10)));
      return response;
    } on Exception {
      debugPrint("checkService failed");
      rethrow;
    }
  }

  /// Checks the session via ```/CheckService```
  Future<RestApiCheckServiceResponse> checkService() async {
    try {
      String function = "_CheckService";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      return RestApiCheckServiceResponse(await _http(HttpMethod.get, requestUri, function));
    } on Exception {
      debugPrint("checkService failed");
      rethrow;
    }
  }

  /// Checks if the session is active and tries to re-login the user if needed.
  ///
  /// retryCount specifies how many time the re-login should be tried.
  ///
  /// Throws exceptions defined in [RestApiResponse]
  Future<RefreshSessionResponse> _refreshSession({int retryCount = 3}) async {
    bool active = false;
    List<RestApiResponse> responses = [];
    int i = 0;
    String newSessionId = "";

    for (i = 1; i < retryCount; i++) {
      RestApiLoginResponse response = await login(_password);
      responses.add(response);
      if (response.isOk) {
        active = true;
        newSessionId = response.sessionId;
        break;
      } else {
        sleep(const Duration(microseconds: 500));
      }
    }

    RefreshSessionResponse sessionResponse =
        RefreshSessionResponse(active, maxRetryCount: retryCount, retryCount: i, sessionId: newSessionId);

    return (sessionResponse);
  }

  Future<RestApiResponse> getFolderByType(String folderType,
      {bool reverseOrder = false, int page = 0, int? perPage, String query = ""}) async {
    try {
      String function = "v1/folders/type";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$folderType";
      Map<String, String> params = {};

      if (reverseOrder) params['reverseOrder'] = reverseOrder.toString();
      params['perPage'] = (perPage ?? _perPageCount).toString();
      if (page > 0) params['page'] = page.toString();
      if (query.isNotEmpty) params['query'] = query;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> postPrintMacrosExecute(String text,
      {String addressOid = "",
      String addressNrOid = "",
      String contactPersonOid = "",
      String incidentOid = "",
      String objectOid = ""}) async {
    try {
      await _refreshSession();

      String function = "v1/printMacros/execute";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      bodyMap['text'] = text;
      if (addressOid.isNotEmpty) bodyMap['address'] = addressOid;
      if (addressNrOid.isNotEmpty) bodyMap['addressNr'] = addressNrOid;
      if (contactPersonOid.isNotEmpty) bodyMap['contactPerson'] = contactPersonOid;
      if (incidentOid.isNotEmpty) bodyMap['incident'] = incidentOid;
      if (objectOid.isNotEmpty) bodyMap['object'] = objectOid;
      body = json.encode(bodyMap);

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getFolderByOid(String oid,
      {bool reverseOrder = false, int page = 0, int? perPage, String query = ""}) async {
    try {
      String function = "v1/folders/oid";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$oid";
      Map<String, String> params = {};

      if (reverseOrder) params['reverseOrder'] = reverseOrder.toString();
      if (page > 0) params['page'] = page.toString();
      params['perPage'] = (perPage ?? _perPageCount).toString();
      if (query.isNotEmpty) params['query'] = query;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getFolderByPath(String path,
      {bool reverseOrder = false, int page = 0, int? perPage, String query = ""}) async {
    try {
      String encodedPath = Uri.encodeComponent(path);
      String function = "v1/folders/path";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$encodedPath";

      Map<String, String> params = {};
      if (reverseOrder) params['reverseOrder'] = reverseOrder.toString();
      if (page > 0) params['page'] = page.toString();
      params['perPage'] = (perPage ?? _perPageCount).toString();
      if (query.isNotEmpty) params['query'] = query.toString();

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to get appointments from given time frame
  ///
  /// [from] Start time
  ///
  /// [to] End time
  ///
  /// [username] Name of the calendar owner, empty is current
  Future<RestApiResponse> getAppointments(DateTime from, DateTime to,
      {String username = "", String? query, int page = 0, int? perPage}) async {
    try {
      String function = "v1/appointments";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};

      params['from'] = from.toISOFormatString();
      params['to'] = to.toISOFormatString();
      params['page'] = page.toString();
      params['perPage'] = (perPage ?? _perPageCount).toString();
      if (username.isNotEmpty) params['username'] = username;
      if (query != null) params['queryString'] = query;
      params['serialization'] = "{\"type\":\"class\",\"style\":\"preview\"}";

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to create new appointment
  Future<RestApiResponse> postAppointments(DateTime from, DateTime to,
      {String title = "",
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
      String rrule = ""}) async {
    try {
      Map<String, dynamic> bodyMap = {};
      Map<String, dynamic> attendeesMap = {};
      String body;

      String function = "v1/appointments";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['from'] = from.toISOFormatString();
      bodyMap['to'] = to.toISOFormatString();
      bodyMap['title'] = title;
      bodyMap['place'] = place;
      bodyMap['description'] = description;
      bodyMap['owner'] = owner;
      if (remindBefore != null) bodyMap['remindBefore'] = remindBefore.toISOFormatString();
      if (remindAt != null) bodyMap['remindAt'] = remindAt.toISOFormatString();
      bodyMap['wholeDay'] = wholeDay;
      if (attendeesUserNames != null) attendeesMap['users'] = attendeesUserNames;
      if (attendeesAddresses != null) attendeesMap['addresses'] = attendeesAddresses;
      if (attendeesEmails != null) attendeesMap['emails'] = attendeesEmails;
      if (notificationComment.isNotEmpty) attendeesMap['notificationComment'] = notificationComment;
      if (notifyAllAttendees) attendeesMap['notifyAllAttendees'] = notifyAllAttendees;
      if (attendeesMap.isNotEmpty) bodyMap['attendees'] = attendeesMap;
      if (type != null) bodyMap['type'] = type;
      if (occupancy != null) bodyMap['occupancy'] = occupancy;
      bodyMap['isSerial'] = isSerial;
      bodyMap['public'] = public;
      bodyMap['extern'] = extern;
      if (rrule.isNotEmpty) bodyMap['rrule'] = rrule;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
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
      DateTime from, DateTime to, DateTime searchArea, List<String> users) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;
      String function = "v1/appointments/nextFreeDate";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['from'] = from.toISOFormatString();
      bodyMap['to'] = to.toISOFormatString();
      bodyMap['searchArea'] = searchArea.toISOFormatString();
      bodyMap['users'] = users;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
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
  Future<RestApiResponse> postAppointmentsInvitation(String id, String action, bool deleteAppointment) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;
      String function = "v1/appointments/$id/invitation";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$action";
      Uri requestUri = _getUri(uriPath);

      bodyMap['deleteAppointment'] = deleteAppointment;

      body = json.encode(bodyMap);

      function = "v1/appointments/id/invitation";
      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiObjectLockResponse> getLockObject(String id) async {
    try {
      String function = "v1/lock/object/$id";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiObjectLockResponse(await _http(HttpMethod.get, requestUri, function));
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
  Future<RestApiResponse> patchAppointmentsRemoveFromSeries(String id, DateTime date) async {
    try {
      String function = "v1/appointments/$id/removeFromSeries";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      Map<String, dynamic> bodyMap = {};
      bodyMap['date'] = date.toISOFormatString();
      String body = json.encode(bodyMap);

      function = "v1/appointments/id/removeFromSeries";
      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to edit an appointment
  ///
  /// [id] OID or ~UUID of appointment
  Future<RestApiResponse> patchAppointmentsUpdateAppointment(String id, DateTime from, DateTime to,
      {String title = "",
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
      String rrule = ""}) async {
    try {
      Map<String, dynamic> attendeesMap = {};
      Map<String, dynamic> bodyMap = {};
      String body;
      String function = "v1/appointments/$id/updateAppointment";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
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
      if (remindAt != null) bodyMap['remindAt'] = remindAt.toISOFormatString();
      bodyMap['wholeDay'] = wholeDay;
      if (attendeesUserNames != null) attendeesMap['users'] = attendeesUserNames;
      if (attendeesAddresses != null) attendeesMap['addresses'] = attendeesAddresses;
      if (attendeesEmails != null) attendeesMap['emails'] = attendeesEmails;
      if (notificationComment.isNotEmpty) attendeesMap['notificationComment'] = notificationComment;
      if (notifyAllAttendees) attendeesMap['notifyAllAttendees'] = notifyAllAttendees;
      if (attendeesMap.isNotEmpty) bodyMap['attendees'] = attendeesMap;
      bodyMap['isSerial'] = isSerial;
      bodyMap['public'] = public;
      bodyMap['extern'] = extern;
      if (type != null) bodyMap['type'] = type;
      if (occupancy != null) bodyMap['occupancy'] = occupancy;  
      if (rrule.isNotEmpty) bodyMap['rrule'] = rrule;

      body = json.encode(bodyMap);

      function = "v1/appointments/id/updateAppointment";
      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
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
  Future<RestApiResponse> patchAppointmentsCreateException(String id, DateTime exceptionFrom, DateTime from, DateTime to,
      {String title = "",
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
      String rrule = ""}) async {
    try {
      Map<String, dynamic> attendeesMap = {};
      Map<String, dynamic> bodyMap = {};
      Map<String, dynamic> exceptionBody = {};
      String body;
      String function = "v1/appointments/$id/createException";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['exceptionFrom'] = exceptionFrom.toISOFormatString();
      exceptionBody['from'] = from.toISOFormatString();
      exceptionBody['to'] = to.toISOFormatString();
      if (title.isNotEmpty) exceptionBody['title'] = title;
      if (place.isNotEmpty) exceptionBody['place'] = place;
      if (description.isNotEmpty) exceptionBody['description'] = description;
      if (owner.isNotEmpty) exceptionBody['owner'] = owner;
      if (remindBefore != const ISODuration(year: 0)) exceptionBody['remindBefore'] = remindBefore.toISOFormatString();
      if (remindAt != null) exceptionBody['remindAt'] = remindAt.toISOFormatString();
      if (wholeDay) exceptionBody['wholeDay'] = wholeDay;
      if (group) exceptionBody['group'] = wholeDay;
      if (attendeesUserNames != null) attendeesMap['users'] = attendeesUserNames;
      if (attendeesAddresses != null) attendeesMap['addresses'] = attendeesAddresses;
      if (attendeesEmails != null) attendeesMap['emails'] = attendeesEmails;
      if (notificationComment.isNotEmpty) attendeesMap['notificationComment'] = notificationComment;
      if (notifyAllAttendees) attendeesMap['notifyAllAttendees'] = notifyAllAttendees;
      if (attendeesMap.isNotEmpty) exceptionBody['attendees'] = attendeesMap;
      if (isSerial) exceptionBody['isSerial'] = isSerial;
      exceptionBody['public'] = public;
      exceptionBody['extern'] = extern;
      if (type != null) exceptionBody['type'] = type;
      if (occupancy != null) exceptionBody['occupancy'] = occupancy;
      if (rrule.isNotEmpty) exceptionBody['rrule'] = rrule;
      bodyMap['exceptionBody'] = exceptionBody;

      body = json.encode(bodyMap);

      function = "v1/appointments/id/createException";
      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to create new email
  Future<RestApiResponse> postMail(
      {String uuid = "",
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
      bool assignAction = false}) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/mail";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};

      if (action.isNotEmpty) params['action'] = action.toString();
      if (actions.isNotEmpty) params['actions'] = actions;
      if (serialization.isNotEmpty) params['serialization'] = serialization;

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
      if (startTime != null) bodyMap['startTime'] = startTime.toISOFormatString();
      priorityBody['priorityValue'] = priorityValue;
      priorityBody['priorityText'] = priorityText;
      bodyMap['assignAddresses'] = assignAddress;
      bodyMap['assignProjects'] = assignProject;
      bodyMap['assignProducts'] = assignProduct;
      bodyMap['assignContacts'] = assignContact;
      bodyMap['assignActions'] = assignAction;
      bodyMap['sendAssignReceiver'] = sendAssignReceiver;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to update existing an email, either the uuid or oid are needed
  Future<RestApiResponse> patchMail(
      {String uuid = "",
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
      DateTime? startTime}) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/mail";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

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
      if (startTime != null) bodyMap['startTime'] = startTime.toISOFormatString();
      priorityBody['priorityValue'] = priorityValue;
      priorityBody['priorityText'] = priorityText;
      bodyMap['priority'] = priorityBody;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// This request allows to update existing email and send it (when body does not contain any OID a new mail is beeing created)
  Future<RestApiResponse> postMailSend(
      {String uuid = "",
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
      String actions = ""}) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/mail/send";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
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
      if (startTime != null) bodyMap['startTime'] = startTime.toISOFormatString();
      priorityBody['priorityValue'] = priorityValue;
      priorityBody['priorityText'] = priorityText;
      bodyMap['priority'] = priorityBody;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// not implemented in df-restapi
  ///
  /// This request allows to reply for an email
  Future<RestApiResponse> postMailReply(String sourceMailOid,
      {String uuid = "",
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
      bool assignAction = false}) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/mail/reply";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$sourceMailOid";
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
      if (startTime != null) bodyMap['startTime'] = startTime.toISOFormatString();
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

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// not implemented in df-restapi
  ///
  /// This request allows to reply all for an email
  Future<RestApiResponse> postMailReplyAll(String sourceMailOid,
      {String uuid = "",
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
      bool assignAction = false}) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/mail/replyAll";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$sourceMailOid";
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
      if (startTime != null) bodyMap['startTime'] = startTime.toISOFormatString();
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

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// not implemented in df-restapi
  ///
  /// This request allows to forward an email
  Future<RestApiResponse> postMailForward(String sourceMailOid,
      {String uuid = "",
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
      bool assignAction = false}) async {
    try {
      Map<String, dynamic> priorityBody = {};
      Map<String, dynamic> bodyMap = {};
      String body;
      String function = "v1/mail/forward";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$sourceMailOid";
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
      if (startTime != null) bodyMap['startTime'] = startTime.toISOFormatString();
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

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getMailAccounts() async {
    try {
      String function = "v1/mail/accounts";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getUserEmailSignatures() async {
    try {
      String function = "v1/userEmailSignatures";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiFileResponse> getFile(String oid) async {
    try {
      String function = "v1/file";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$oid";
      Uri requestUri = _getUri(uriPath);

      await checkSession();

      HttpMetric? metric =
          !kIsWeb ? performance?.newHttpMetric("https://gsd-software.com/$function", firebase_performance.HttpMethod.Post) : null;
      await metric?.start();

      Response httpResponse = await http.get(requestUri, headers: _getHeader()).timeout(const Duration(seconds: 60));
      final response = RestApiFileResponse(httpResponse);

      metric?.httpResponseCode = httpResponse.statusCode;
      metric?.responsePayloadSize = httpResponse.contentLength;
      metric?.responseContentType = httpResponse.headers['content-type'];
      await metric?.stop();

      return (response);
    } catch (_) {
      rethrow;
    }
  }

  Future<Uint8List?> getPreview(String objectOid, String parameters, {int page = 0, bool keepRatio = true}) async {
    try {
      Uint8List? bytes;

      String keepRatioPath = keepRatio ? "/keep-ratio" : "/";
      String objectOidPath = "/$objectOid";
      String pagePath = "/$page";

      String function = "v1/preview";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$parameters$keepRatioPath$objectOidPath$pagePath";
      Uri requestUri = _getUri(uriPath);

      await checkSession();

      HttpMetric? metric =
          !kIsWeb ? performance?.newHttpMetric("https://gsd-software.com/$function", firebase_performance.HttpMethod.Post) : null;
      await metric?.start();

      Response httpResponse = await http.get(requestUri, headers: _getHeader()).timeout(const Duration(seconds: 60));

      metric?.httpResponseCode = httpResponse.statusCode;
      metric?.responsePayloadSize = httpResponse.contentLength;
      metric?.responseContentType = httpResponse.headers['content-type'];
      await metric?.stop();

      if (httpResponse.statusCode == 200) {
        bytes = httpResponse.bodyBytes;
      }

      return bytes;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getDFConfig() async {
    try {
      String function = "v1/execute/xDFAppGetConfig";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);
      String requestBodyJson = '{}';

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: requestBodyJson));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getEmailSuggestions(String searchtext) async {
    try {
      String function = "v1/execute/xDFAppGetEMailAddressSuggestions";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);
      String body = "";

      Map<String, dynamic> bodyMap = {};
      bodyMap["searchtext"] = searchtext;

      body = jsonEncode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> createDemoAccount(String password) async {
    try {
      String function = "v1/DF/CreateDemoUser";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);
      String body = "";

      Map<String, dynamic> bodyMap = {};
      bodyMap["deviceId"] = device?.deviceId;
      bodyMap["password"] = password;

      body = jsonEncode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// gets object data
  Future<RestApiResponse> getObject(String objectOid, {String className = "", String serialization = ""}) async {
    try {
      String function = "v1/object";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$objectOid";
      Map<String, String> params = {};

      if (className.isNotEmpty) params['class'] = className;
      if (serialization.isNotEmpty) params['serialization'] = serialization;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// gets unread documents
  Future<RestApiResponse> getPersonalUnreadDocuments() async {
    try {
      String function = "v1/personal/unreadDocuments";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// gets personal actions
  Future<RestApiResponse> getPersonalMyTasks() async {
    try {
      String function = "v1/personal/myTasks";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// action get sub actions
  Future<RestApiResponse> getIncidentTree(String oid,
      {int deepLevel = -1, String serialization = "", String rightsControlKey = ""}) async {
    try {
      String function = "v1/incidentTree";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$oid";
      Map<String, String> params = {};

      if (deepLevel != -1) params['deepLevel'] = deepLevel.toString();
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// clears recycle bin
  Future<RestApiResponse> patchPersonalEmptyRecycleBin() async {
    try {
      String function = "v1/personal/emptyRecycleBin";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// creates an object
  Future<RestApiResponse> postObject(String className, String body,
      {int storeMode = 0, String serialization = "", String actions = "", String rightsControlKey = ""}) async {
    try {
      String function = "v1/object";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$className";
      Map<String, String> params = {};

      // default 0: DBOModifyMember... | 10: DBOSet...
      if (storeMode != 0) params['storeMode'] = storeMode.toString();
      // example: [{ "type": "sendObject", "toUser": "demo", "text": "Hello world"}]
      if (actions.isNotEmpty) params['actions'] = actions;
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// creates a draft message
  Future<RestApiResponse> postMessage(List<String> toUsers, String text,
      {String name = "",
      String description = "",
      bool addToIncomingFolder = true,
      String originalOid = "",
      String uuid = "",
      String serialization = "",
      String rightsControlKey = ""}) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/message";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};

      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['toUsers'] = toUsers;
      bodyMap['text'] = text;
      if (uuid.isNotEmpty) bodyMap['~UUID'] = uuid;
      if (name.isNotEmpty) bodyMap['name'] = name;
      if (description.isNotEmpty) bodyMap['description'] = description;
      if (addToIncomingFolder) bodyMap['addToIncomingFolder'] = addToIncomingFolder;
      if (originalOid.isNotEmpty) bodyMap['originalOid'] = originalOid;
      if (name.isNotEmpty) bodyMap['name'] = name;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// creates a message and sends it
  Future<RestApiResponse> postMessageSend(List<String> toUsers, String text,
      {String name = "",
      String description = "",
      bool addToIncomingFolder = true,
      String originalOid = "",
      String uuid = "",
      String serialization = "",
      String rightsControlKey = ""}) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/message/send";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};

      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['toUsers'] = toUsers;
      bodyMap['text'] = text;
      if (uuid.isNotEmpty) bodyMap['~UUID'] = uuid;
      if (name.isNotEmpty) bodyMap['name'] = name;
      if (description.isNotEmpty) bodyMap['description'] = description;
      if (addToIncomingFolder) bodyMap['addToIncomingFolder'] = addToIncomingFolder;
      if (originalOid.isNotEmpty) bodyMap['originalOid'] = originalOid;
      if (name.isNotEmpty) bodyMap['name'] = name;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// edit a  draft message
  Future<RestApiResponse> patchMessage(String oid, List<String> toUsers, String text,
      {String name = "",
      String description = "",
      bool addToIncomingFolder = true,
      String originalOid = "",
      String uuid = "",
      String serialization = "",
      String rightsControlKey = ""}) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/message";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$oid";
      Map<String, String> params = {};

      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['toUsers'] = toUsers;
      bodyMap['text'] = text;
      if (uuid.isNotEmpty) bodyMap['~UUID'] = uuid;
      if (name.isNotEmpty) bodyMap['name'] = name;
      if (description.isNotEmpty) bodyMap['description'] = description;
      if (addToIncomingFolder) bodyMap['addToIncomingFolder'] = addToIncomingFolder;
      if (originalOid.isNotEmpty) bodyMap['originalOid'] = originalOid;
      if (name.isNotEmpty) bodyMap['name'] = name;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// edit and send a message
  Future<RestApiResponse> patchMessageSend(String oid, List<String> toUsers, String text,
      {String name = "",
      String description = "",
      bool addToIncomingFolder = true,
      String originalOid = "",
      String uuid = "",
      String serialization = "",
      String rightsControlKey = ""}) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/message/send";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$oid";
      Map<String, String> params = {};

      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['toUsers'] = toUsers;
      bodyMap['text'] = text;
      if (uuid.isNotEmpty) bodyMap['~UUID'] = uuid;
      if (name.isNotEmpty) bodyMap['name'] = name;
      if (description.isNotEmpty) bodyMap['description'] = description;
      if (addToIncomingFolder) bodyMap['addToIncomingFolder'] = addToIncomingFolder;
      if (originalOid.isNotEmpty) bodyMap['originalOid'] = originalOid;
      if (name.isNotEmpty) bodyMap['name'] = name;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// creates a sub folder
  Future<RestApiResponse> postFolders(String folderName, String parentFolder,
      {RestApiFolderType parentFolderSourceType = RestApiFolderType.path}) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/folders";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['folderName'] = folderName;
      bodyMap['parentFolder'] = parentFolder;
      bodyMap['parentFolderSourceType'] = parentFolderSourceType.value;
      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// deletes a folder
  Future<RestApiResponse> deleteFolders(String path) async {
    try {
      String function = "v1/folders";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};
      if (path.isNotEmpty) params['path'] = path;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.delete, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// renames a folder
  Future<RestApiResponse> patchFoldersRename(String oid, String newName) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/folders/rename";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$oid";
      Uri requestUri = _getUri(uriPath);

      bodyMap['folderName'] = newName;
      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// adds a list of document oids to a folder
  Future<RestApiResponse> patchFoldersAdd(RestApiFolderType folderType, String folderId, List<String> documentOids,
      {String className = ""}) async {
    try {
      Map<String, dynamic> documentsMap = {};
      String body;
      String folderTypeEncoded = Uri.encodeComponent(folderType.value);
      String folderIdEncoded = Uri.encodeComponent(folderId);
      String function = "v1/folders/add";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$folderTypeEncoded/$folderIdEncoded";
      Map<String, String> params = {};

      // class: In case one would like to add something from favorite or history it is necessary to provide the class of objects you would like to add
      if (className.isNotEmpty) params['class'] = className;
      Uri requestUri = _getUri(uriPath, params: params);

      documentsMap['documents'] = documentOids;
      body = json.encode(documentsMap);

      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// removes a list of document oids from a folder
  Future<RestApiResponse> patchFoldersRemoveDocuments(RestApiFolderType folderType, String folderId, List<String> documentOids,
      {String className = "", bool moveToTrashBin = true, deep = false}) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String folderTypeEncoded = Uri.encodeComponent(folderType.value);
      String folderIdEncoded = Uri.encodeComponent(folderId);
      String function = "v1/folders/remove";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$folderTypeEncoded/$folderIdEncoded";
      Map<String, String> params = {};

      // class: In case one would like to remove something from favorite or history it is necessary to provide the class of objects you would like to remove
      if (className.isNotEmpty) params['class'] = className;
      Uri requestUri = _getUri(uriPath, params: params);

      bodyMap['documents'] = documentOids;
      bodyMap['moveToTrashBin'] = moveToTrashBin;
      bodyMap['deep'] = deep;
      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// removes a list of document oids from a folder
  Future<RestApiResponse> patchFoldersCopyDocuments(RestApiFolderType destinationFolderSourceType, String destinationFolderId, List<String> documentOids, {RestApiFolderType? sourceFolderSourceType, String? sourceFolderId, bool cut = true}) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/folders/copyDocuments";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";

      Uri requestUri = _getUri(uriPath);

      bodyMap['destinationFolderSourceType'] = destinationFolderSourceType.value;
      bodyMap['destinationFolder'] = destinationFolderId;
      if(sourceFolderSourceType != null) bodyMap['sourceFolderSourceType'] = sourceFolderSourceType.value;
      if(sourceFolderId != null) bodyMap['sourceFolder'] = sourceFolderId;
      bodyMap['documents'] = documentOids;
      bodyMap['cut'] = cut;
      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// marks documents a read/unread
  ///
  /// ids: list of oid's or uuid's
  ///
  /// read: default = true
  Future<RestApiResponse> putDocsRead(List<String> ids, {bool read = true}) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/docs/read";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['read'] = read;
      bodyMap['ids'] = ids;
      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.put, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// marks documents as not new
  ///
  /// ids: list of oid's or uuid's
  ///
  /// read: default = true
  Future<RestApiResponse> putDocsNotNew(List<String> ids) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/docs/removeDocFromNewDocuments";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['ids'] = ids;
      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.put, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// adds objects to the history or clears class history
  ///
  /// ids: list of object oid's or uuid's
  ///
  /// action: "add" | "remove"
  ///
  /// className: add to clear the class history "Vorgang", "Adresse", "Projekt", "Produkt", "Ansprechpartner", "Dokument"
  ///
  /// examples:
  ///
  /// add objects:  {action: "add", ids: ["1234","5678"]}
  ///
  /// clear class: {action: "remove", class: "Vorgang",  ids: ["1234"]}
  Future<RestApiResponse> putDocsHistory(
    List<String> ids, {
    String action = "add",
    String className = "",
  }) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/docs/history";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['action'] = action;
      bodyMap['ids'] = ids;

      if (className.isNotEmpty) {
        bodyMap['className'] = className;
      }

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.put, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// edit object
  Future<RestApiResponse> patchObject(String objectOid, String body,
      {int storeMode = 0,
      int storeSecurityPolice = 0,
      String serialization = "",
      String actions = "",
      String rightsControlKey = ""}) async {
    try {
      String function = "v1/object";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$objectOid";
      Map<String, String> params = {};

      // default 0: DBOModifyMember... | 10: DBOSet...
      if (storeMode != 0) params['storeMode'] = storeMode.toString();
      // 0	EQ | 10 GT_NOLIST | 20	GT | 30	ANY_NOLIST | 40	ANY | 50	DIFF_NOLIST | 60	DIFF
      if (storeSecurityPolice != 0) params['storeSecurityPolice'] = storeSecurityPolice.toString();
      // example: [{ "type": "sendObject", "toUser": "demo", "text": "Hello world"}]
      if (actions.isNotEmpty) params['actions'] = actions;
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// delets an object
  Future<RestApiResponse> deleteObject(String objectOid, {String actions = ""}) async {
    try {
      String function = "v1/object";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$objectOid";
      Uri requestUri;
      Map<String, String> params = {};

      if (actions.isNotEmpty) params['actions'] = actions;
      requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.delete, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// gets object list data
  Future<RestApiResponse> getObjects(className,
      {String query = "", int page = 0, int? perPage, String serialization = "", String rightsControlKey = ""}) async {
    try {
      String function = "v1/objects";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$className";
      Map<String, String> params = {};

      if (query.isNotEmpty) params['query'] = query.toString();
      if (page != 0) params['page'] = page.toString();
      params['perPage'] = (perPage ?? _perPageCount).toString();
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  /// patch objects data
  Future<RestApiResponse> patchObjects(className,
      {String query = "",
      String body = "",
      int storeMode = 0,
      int storeSecurityPolice = 0,
      String serialization = "",
      String actions = "",
      String rightsControlKey = ""}) async {
    try {
      String function = "v1/objects";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$className";
      Map<String, String> params = {};

      if (query.isNotEmpty) params['query'] = query.toString();
      if (actions.isNotEmpty) params['actions'] = actions;
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;
      if (storeSecurityPolice != 0) params['storeSecurityPolice'] = storeSecurityPolice.toString();
      if (storeMode != 0) params['storeMode'] = storeMode.toString();

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getCalls(
      {String query = "", int page = 0, int? perPage, String serialization = "", String rightsControlKey = ""}) async {
    try {
      String function = "v1/calls";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};

      if (query.isNotEmpty) params['query'] = query.toString();
      if (page != 0) params['page'] = page.toString();
      params['perPage'] = (perPage ?? _perPageCount).toString();
      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getModelStructure(
      {String classes = "", String baseClasses = "", bool skipMembers = false, String rightsControlKey = ""}) async {
    try {
      String function = "v1/model/structure";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};

      if (classes.isNotEmpty) params['classes'] = classes;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getExtModelStructure(
      {String classes = "", String baseClasses = "", bool skipMembers = false, String rightsControlKey = ""}) async {
    try {
      String function = "v1/extModel/structure";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};

      if (classes.isNotEmpty) params['classes'] = classes;
      if (baseClasses.isNotEmpty) params['baseClasses'] = baseClasses;
      if (skipMembers) params['skipMembers'] = skipMembers.toString();
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getExtModelML({List<String>? headerClasses, List<String>? bodyClasses, bool skipMembers = false}) async {
    try {
      String function = "v1/extModel/ml";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};
      Map<String, dynamic> bodyMap = {};
      String body;

      if (headerClasses != null && headerClasses.isNotEmpty) params['ml'] = jsonEncode(headerClasses);
      if (skipMembers) params['skipMembers'] = skipMembers.toString();

      if (bodyClasses != null && bodyClasses.isNotEmpty) bodyMap['ml'] = bodyClasses;
      body = bodyMap.isNotEmpty ? json.encode(bodyMap) : "";

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(bodyClasses == null ? HttpMethod.get: HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getExtModelIndexes({String classes = "", String rightsControlKey = ""}) async {
    try {
      String function = "v1/extModel/indexes";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};

      if (classes.isNotEmpty) params['classes'] = classes;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;
      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getModelDict(String dict, {String langID = "", String rightsControlKey = ""}) async {
    try {
      String function = "v1/model/dict";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> params = {};

      params['dict'] = dict;
      if (langID.isNotEmpty) params['langID'] = langID;
      if (rightsControlKey.isNotEmpty) params['rightsControlKey'] = rightsControlKey;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> logout() async {
    try {
      String function = "v1/logout";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      _loggedIn = false; 
      _manualLoggedOut = true;
      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    } finally {
      _sessionId = "";
      sessionIdChangedEvent.broadcast();
    }
  }

  Future<RestApiResponse> uploadFile(String pathToFile,
      {PlatformFile? webFile, String replaceOID = "", bool patch = true, bool fetchToObject = true, out}) async {
    try {
      String function = "v1/uploadFile";

      RestApiResponse restApiResponse = await _getUploadID();

      String uploadID = jsonDecode(restApiResponse.httpResponse.body)["data"]["uploadId"];

      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$uploadID";
      Uri requestUri = _getUri(uriPath);

      Map<String, String> requestHeader = _getHeader(contentType: "application/x-www-form-urlencoded");

      //Sending
      debugPrint("Uploadfile send: $requestUri");
      debugPrint("Request Header: $requestHeader");

      HttpMetric? metric =
          !kIsWeb ? performance?.newHttpMetric("https://gsd-software.com/$function", firebase_performance.HttpMethod.Post) : null;
      await metric?.start();

      var request = http.MultipartRequest('POST', requestUri);

      if (webFile == null) {
        request.files.add(await http.MultipartFile.fromPath('', pathToFile));
      } else {
        request.files.add(http.MultipartFile.fromBytes("", webFile.bytes ?? [], filename: webFile.name));
      }

      request.headers.addAll(requestHeader);

      http.StreamedResponse httpResponse = await request.send();

      metric?.httpResponseCode = httpResponse.statusCode;
      metric?.responsePayloadSize = httpResponse.contentLength;
      metric?.responseContentType = httpResponse.headers['content-type'];
      await metric?.stop();

      if (httpResponse.statusCode != 200) {
        throw Exception("Can not upload file");
      }
      
      if(fetchToObject) {
        return await _fetchUploadFile(uploadID, replaceOID);
      } else {
        return restApiResponse;
      }
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> _fetchUploadFile(String uploadID, String replaceOID) async {
    try {
      String function = "v1/uploadFile";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$uploadID";
      Map<String, String> params = {};

      if (replaceOID.isNotEmpty) params['replaceOID'] = replaceOID;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.patch, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> _getUploadID() async {
    try {
      String function = "v1/uploadFile";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> postUserSettings(String key, Map<String, dynamic> data) async {
    try {
      String function = "v1/userSetting";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$key";
      Uri requestUri = _getUri(uriPath);

      String requestBodyJson = jsonEncode(data);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: requestBodyJson));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> docAnnotationsSetRead(String docOid) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/execute/xDFAppDocumentAnnotationsSetRead";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap['object'] = docOid;
      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getDefaultEMailTemplate() async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/execute/xDFAppGetDefaultEMailTemplate";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> convertEMailPlaintextToHTML(String content) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/execute/xDFAppConvertPlaintextToHTML";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap["content"] = content;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> convertEMailHTMLToPlaintext(String content) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/execute/xDFAppConvertHTMLToPlaintext";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap["content"] = content;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getEmailReplyData(String emailOid) async {
    try {
      Map<String, dynamic> bodyMap = {};
      String body;

      String function = "v1/execute/xDFAppGetEMailReplyData";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      bodyMap["email"] = emailOid;

      body = json.encode(bodyMap);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> postLicenseRelease(List<String> appnames, String sessionId) async {
    try {
      String function = "v1/license/release";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> requestHeader = _getHeader();
      Uri requestUri = _getUri(uriPath);
      Map<String, dynamic> requestBodyMap = {};
      String bodyText;

      requestBodyMap['appNames'] = appnames;
      bodyText = jsonEncode(requestBodyMap);

      requestHeader["sessionId"] = sessionId;

      final response = RestApiResponse(
          await _http(HttpMethod.post, requestUri, function, requestHeader: requestHeader, body: bodyText, handleSession: false));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiUserSystemSettingsResponse> getUserSystemSettings() async {
    try {
      String function = "v1/userSystemSettings";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiUserSystemSettingsResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiVersionInfoResponse> getVersionInfo() async {
    try {
      String function = "v1/versioninfo";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiVersionInfoResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> postPZEClockIn({String? employeeoid, String? key}) async {
    try {
      String function = "v1/pze/clockIn";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, dynamic> bodyMap = {};
      String body;

      if (employeeoid != null) bodyMap['employeeoid'] = employeeoid;
      if (key != null) bodyMap['key'] = key;

      body = json.encode(bodyMap);

      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function, body: body));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> postPZEClockOut({String? employeeoid}) async {
    try {
      String function = "v1/pze/clockOut";
      Map<String, String> params = {};
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";

      if (employeeoid != null) params['employeeoid'] = employeeoid;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getPZEWorkingTimeKeys({String serialization = ""}) async {
    try {
      String function = "v1/pze/workingTimeKeys";
      Map<String, String> params = {};
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";

      if (serialization.isNotEmpty) params['serialization'] = serialization;

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getPZEWorkingTimeAccounts({String serialization = "", String? employeeOid, DateTime? from, DateTime? to}) async {
    try {
      String function = "v1/pze/workingTimeAccounts";
      Map<String, String> params = {};
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";

      if (serialization.isNotEmpty) params['serialization'] = serialization;
      if (employeeOid != null) params['employeeOid'] = employeeOid;
      if (from != null) params['from'] = from.toISOFormatString();
      if (to != null) params['to'] = to.toISOFormatString();

      Uri requestUri = _getUri(uriPath, params: params);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiResponse> getUserAssignments() async {
    try {
      String function = "v1/execute/xDFAppGetUserAssignments";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(await _http(HttpMethod.post, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiLoginSecureKeyResponse> getLoginSecureKey() async {
    try {
      String function = "v2/login/secure/key";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> requestHeader = _getHeader(addSessionId: false);
      Uri requestUri = _getUri(uriPath);

      final response = RestApiLoginSecureKeyResponse(
          await _http(HttpMethod.get, requestUri, function, requestHeader: requestHeader, handleSession: false));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<RestApiLoginSecureKeyResponse> getLoginKey() async {
    try {
      String function = "v2/login/key";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function";
      Map<String, String> requestHeader = _getHeader(addSessionId: false);
      Uri requestUri = _getUri(uriPath);

      final response = RestApiLoginSecureKeyResponse(
          await _http(HttpMethod.get, requestUri, function, requestHeader: requestHeader, handleSession: false));
      return response;
    } catch (_) {
      rethrow;
    }
  }

  Future<String> _getv2LoginSecureBody(String clearBody, String serverPublicKeyString) async {
    // Öffnen des öffentlichen Schlüssels
    final publicKey = serverPublicKeyString.parsePublicKeyFromPem();

    await EncryptionManager().initializeRSAKeyPair();

    // Daten verschlüsseln
    final encryptedBase64 = await EncryptionManager().encryptRSAInBlocks(clearBody, publicKey: publicKey);

    RSAPublicKey rsaPublicKey = EncryptionManager().keyRSA!.publicKey;

    String rsaPublicKeyPEM = rsaPublicKey.encodeToPem();

    // Der öffentliche Schlüssel im PEM-Format, ebenfalls base64-kodiert
    final publicKeyBase64 = base64.encode(utf8.encode(rsaPublicKeyPEM));

    // Anfragenkörper erstellen
    Map<String, dynamic> requestBody = {
      "credentials": encryptedBase64,
      "publicKey": publicKeyBase64,
    };

    return jsonEncode(requestBody);
  }

  Future<String> _getv2LoginBody(String clearBody, String serverPublicKeyString) async {
    // Öffnen des öffentlichen Schlüssels
    final publicKey = serverPublicKeyString.parsePublicKeyFromPem();

    await EncryptionManager().initializeRSAKeyPair();
    await EncryptionManager().initializeAESKey();

    Map<String, dynamic> encryptedBodyJson = jsonDecode(await EncryptionManager().encryptAES(clearBody, padding: "PKCS7"));

    Uint8List encryptedBodyIv = base64Decode(encryptedBodyJson["iv"] ?? "");
    Uint8List encryptedBodyData = base64Decode(encryptedBodyJson["data"] ?? "");

    Uint8List encryptedBodyMerged = Uint8List(encryptedBodyIv.length + encryptedBodyData.length);
    encryptedBodyMerged.setRange(0, encryptedBodyIv.length, encryptedBodyIv);
    encryptedBodyMerged.setRange(encryptedBodyIv.length, encryptedBodyMerged.length, encryptedBodyData);

    // Daten verschlüsseln
    final encryptedBodyBase64 = base64.encode(encryptedBodyMerged);

    final encryptedAesKeyBase64 =
        base64.encode(await EncryptionManager().encryptRSA(EncryptionManager().keyAES!.bytes, publicKey: publicKey));

    // Der öffentliche Schlüssel im PEM-Format, ebenfalls base64-kodiert
    final publicKeyBase64 = EncryptionManager().keyRSA!.publicKey.encodeToPem();

    // Anfragenkörper erstellen
    Map<String, dynamic> requestBody = {
      "aesKey": encryptedAesKeyBase64,
      "data": encryptedBodyBase64,
      "publicKey": publicKeyBase64
    };

    return jsonEncode(requestBody);
  }

  Future<RestApiResponse> getDocumentPaths( String oid) async {
    try {
      String function = "v1/docs/documentPaths";
      String uriPath = "${alias.isEmpty ? "" : "/$alias"}/$function/$oid";
      Uri requestUri = _getUri(uriPath);

      final response = RestApiResponse(await _http(HttpMethod.get, requestUri, function));
      return response;
    } catch (_) {
      rethrow;
    }
  }

}
