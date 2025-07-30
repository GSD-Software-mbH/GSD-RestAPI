/// Exception thrown when the web-service is returning an error code
/// for all error codes check https://docs.gsd.pl/restapi/errorCodes/errorCodes/
class TokenOrSessionIsMissingException implements Exception {
  /// A message describing the format error.
  String message;

  /// The actual 'statusCode' from the http-response
  String statusCode;

  /// The actual 'statusMessage' from the http-response
  String statusMessage;

  /// Creates a new `WebServiceException` with an optional error [message].
  ///
  /// Optionally also supply the actual [statusCode] and [statusMessage] from the web-service response
  TokenOrSessionIsMissingException([this.message = "", this.statusCode = "", this.statusMessage = ""]);
}
