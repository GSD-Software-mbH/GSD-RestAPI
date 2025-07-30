/// Exception thrown when the http-request is returning an error code
/// and there for the web-service could not be reached.
class HttpRequestException implements Exception {
  /// A message describing the format error.
  String message;

  /// The actual 'statusCode' from the http-response
  String statusCode;

  /// The actual 'statusMessage' from the http-response
  String? reasonPhrase;

  /// Creates a new `HttpResponseException` with an optional error [message].
  ///
  /// Optionally also supply the actual [statusCode] and [reasonPhrase] from the http response
  HttpRequestException(this.message, this.statusCode,
      {this.reasonPhrase = ""});
}
