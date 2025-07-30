import 'package:restapi/restapidevicetype.dart';

/// [RestApiDevice] used to login the device
class RestApiDevice {
  /// Device on which you would like to login
  String deviceId = "";

  /// Device name
  String device = "";

  /// Version of the system
  String systemVersion = "";

  /// Firebase token
  String fireBaseToken = "";

  /// 0 Unknown
  RestApiDeviceType deviceType = RestApiDeviceType.unkown;

  /// System version
  String systemString = "";

  /// Creates a new `RestApiDevice`
  RestApiDevice(this.deviceId,
      {this.device = "",
      this.systemVersion = "",
      this.fireBaseToken = "",
      this.deviceType = RestApiDeviceType.unkown,
      this.systemString = ""});

  Map<String,dynamic> toJson() => {
        'deviceId': deviceId,
        'device': device,
        'systemVersion': systemVersion,
        'firebaseToken': fireBaseToken,
        'deviceType': deviceType.id.toString(),
        'systemType': deviceType.id.toString(),
        'systemString': systemString
      };
}
     