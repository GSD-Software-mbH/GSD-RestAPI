part of 'gsd_restapi.dart';

class RestApiHttpMetric {
  Duration? get duration {
    if (_startTime != null && _stopTime != null) {
      return _stopTime!.difference(_startTime!);
    }
    return null;
  }

  DateTime? get startTime => _startTime;

  DateTime? get stopTime => _stopTime;

  final String path;
  final HttpMethod method;
  DateTime? _startTime;
  DateTime? _stopTime;
  int? responseCode;
  int? requestPayloadSize;
  int? responsePayloadSize;
  String? responseContentType;

  RestApiHttpMetric(this.path, this.method);

  void start() {
    _startTime = DateTime.now();
  }

  void stop() {
    _stopTime = DateTime.now();
  }

  Map<String, dynamic> toMap() {
    return {
      'path': path,
      'method': method,
      'startTime': _startTime?.toIso8601String(),
      'stopTime': _stopTime?.toIso8601String(),
      'duration': duration?.inMilliseconds,
      'responseCode': responseCode,
      'requestPayloadSize': requestPayloadSize,
      'responsePayloadSize': responsePayloadSize,
      'responseContentType': responseContentType,
    };
  }
}
