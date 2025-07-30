import 'package:http/http.dart' as http;
import 'package:restapi/exception/httprequestexception.dart';

/// Base class rest-api responses
class RestApiFileResponse {
  /// Response from the http.request
  final http.Response _httpResponse;

  /// Success: _isOk = true | Error: _isOk = false
  bool _isOk = false;

  http.Response get httpResponse => _httpResponse;
  bool get isOk => _isOk;

  /// Creates a [RestApiResponse] object based on a [http.Response]
  ///
  /// Throws an [HttpRequestException] if the statusCode from the [http.Response] is not '200'

  RestApiFileResponse(this._httpResponse) {
    if (httpResponse.statusCode != 200) {
      throw HttpRequestException(
          "HTTPResponseException: ${httpResponse.statusCode} ${httpResponse.reasonPhrase}", httpResponse.statusCode as String,
          reasonPhrase: httpResponse.reasonPhrase);

      // possible to extract status / internalstatus / statusMessage if 404
    } else {
      _isOk = true;
    }
  }
}
