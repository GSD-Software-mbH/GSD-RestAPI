
import 'package:http/http.dart' as http;
import 'dart:convert';

import 'package:restapi/exception/httprequestexception.dart';
import 'package:restapi/exception/licenseexception.dart';
import 'package:restapi/exception/sessioninvalidexception.dart';
import 'package:restapi/exception/tokenorsessionismissingexception.dart';
import 'package:restapi/exception/userandpasswrongexception.dart';
import 'package:restapi/exception/webserviceexepection.dart';

/// Base class rest-api responses
class RestApiResponse {
  /// Response from the http.request
  final http.Response _httpResponse;

  /// Field 'status.internalStatus' from the [httpResponse.body]
  String _internalStatus = "0";

  /// Field 'status.statusMessage' from the [httpResponse.body]
  String _statusMessage = "";

  /// Success: _isOk = true | Error: _isOk = false
  bool _isOk = false;

  http.Response get httpResponse => _httpResponse;
  String get internalStatus => _internalStatus;
  String get statusMessage => _statusMessage;
  bool get isOk => _isOk;

  /// Creates a [RestApiResponse] object based on a [http.Response]
  ///
  /// Throws an [HttpRequestException] if the statusCode from the [http.Response] is not '200'
  ///
  /// Throws an [FormatException] if the [http.Response.body] is missing the following fields: 'status', 'status.internalStatus', status.statusMessage'
  ///
  /// Throws an [WebServiceException] if the response from web-service is not '0' OK for all the possible error codes check https://docs.gsd.pl/restapi/errorCodes/errorCodes/
  RestApiResponse(this._httpResponse) {
    Map<String, dynamic> responseJson;

    try {
      responseJson = jsonDecode(httpResponse.body);
    } catch (e) {
      rethrow;
    }

    if (!responseJson.containsKey("status")) {

      throw HttpRequestException(
          "HTTPResponseException: ${httpResponse.statusCode} ${httpResponse.reasonPhrase}", httpResponse.statusCode as String,
          reasonPhrase: httpResponse.reasonPhrase);
    } else {
      var statusJson = responseJson['status'];
      if (!statusJson.containsKey("internalStatus")) {
        throw FormatException("missing 'status.internalStatus' field in response body", responseJson);
      } else {
        _internalStatus = statusJson['internalStatus'];
      }

      if (!statusJson.containsKey("statusMessage")) {
        throw FormatException("missing 'status.statusMessage' field in response body", responseJson);
      } else {
        _statusMessage = statusJson['statusMessage'];
      }
    }

    if (_internalStatus == "0") {

      _isOk = true;
    } else if (_internalStatus == "201") {
      throw SessionInvalidException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    } else if (_internalStatus == "204") {
      throw TokenOrSessionIsMissingException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    } else if (_internalStatus == "302") {
      throw UserAndPassWrongException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    } else if (_internalStatus == "306" || _internalStatus == "101") {
      throw LicenseException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    } else {
      throw WebServiceException("webservice error: $_internalStatus $_statusMessage", _internalStatus, _statusMessage);
    }
  }
}
