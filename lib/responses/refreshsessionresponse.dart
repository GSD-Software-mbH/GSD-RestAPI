
class RefreshSessionResponse {
  get isActive => _isActive;

  int maxRetryCount;
  int retryCount;
  String message;
  String sessionId;

  final bool _isActive;

  RefreshSessionResponse(this._isActive,
      {this.retryCount = 0,
      this.maxRetryCount = 0,
      this.message = "",
      this.sessionId = ""});
}
