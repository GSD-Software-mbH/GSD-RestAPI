part of 'restapi.dart';

/// Repräsentiert ein Gerät, das sich bei der REST-API anmeldet
/// 
/// Diese Klasse enthält alle relevanten Informationen über ein Gerät,
/// die für die Authentifizierung und Identifikation bei der REST-API benötigt werden.
class RestApiDevice {
  /// Eindeutige Geräte-ID zur Identifizierung des Geräts
  /// 
  /// Diese ID sollte für jedes Gerät eindeutig sein und wird verwendet,
  /// um das Gerät bei wiederholten Anmeldungen zu erkennen.
  String deviceId = "";

  /// Anzeigename des Geräts (z.B. "iPhone 13", "Samsung Galaxy S21")
  String device = "";

  /// Version des Betriebssystems (z.B. "iOS 15.0", "Android 12")
  String systemVersion = "";

  /// Firebase-Token für Push-Benachrichtigungen
  /// 
  /// Wird verwendet, um Push-Benachrichtigungen an das Gerät zu senden.
  String fireBaseToken = "";

  /// Typ des Geräts (Android, iOS, Web, etc.)
  /// 
  /// Standard ist "unknown" (0), wenn nicht anders angegeben.
  RestApiDeviceType deviceType = RestApiDeviceType.unkown;

  /// Detaillierte Systembeschreibung
  /// 
  /// Kann zusätzliche Informationen über das System enthalten.
  String systemString = "";

  /// Erstellt eine neue RestApiDevice-Instanz
  /// 
  /// [deviceId] - Eindeutige Geräte-ID (erforderlich)
  /// [device] - Anzeigename des Geräts (optional)
  /// [systemVersion] - Betriebssystemversion (optional)
  /// [fireBaseToken] - Firebase-Token (optional)
  /// [deviceType] - Gerätetyp (optional, Standard: unknown)
  /// [systemString] - Systembeschreibung (optional)
  RestApiDevice(this.deviceId,
      {this.device = "",
      this.systemVersion = "",
      this.fireBaseToken = "",
      this.deviceType = RestApiDeviceType.unkown,
      this.systemString = ""});

  /// Konvertiert das Gerät in ein JSON-Map für API-Aufrufe
  /// 
  /// Diese Methode serialisiert alle Geräteinformationen in ein JSON-Format,
  /// das für REST-API-Aufrufe verwendet werden kann.
  /// 
  /// **Wichtig:** Der Firebase-Token wird als 'firebaseToken' (ohne 'B') 
  /// im JSON gespeichert, um mit der API-Spezifikation übereinzustimmen.
  /// 
  /// **Returns:** [Map<String, dynamic>] mit allen Geräteinformationen:
  /// * `deviceId` - Die eindeutige Geräte-ID
  /// * `device` - Der Anzeigename des Geräts
  /// * `systemVersion` - Die Betriebssystemversion
  /// * `firebaseToken` - Der Firebase-Token für Push-Benachrichtigungen
  /// * `deviceType` - Die numerische ID des Gerätetyps
  /// * `systemType` - Alias für deviceType (API-Kompatibilität)
  /// * `systemString` - Zusätzliche Systeminformationen
  /// 
  /// **Beispiel:**
  /// ```dart
  /// var device = RestApiDevice('device-123', 
  ///   device: 'iPhone 13',
  ///   deviceType: RestApiDeviceType.ios
  /// );
  /// var json = device.toJson();
  /// print(json['deviceId']); // 'device-123'
  /// ```
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
     