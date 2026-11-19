import 'package:gsd_restapi/src/models/gsd_docuframe_device_type.dart';

/// Repräsentiert ein Gerät, das sich bei der REST-API anmeldet
///
/// Diese Klasse enthält alle relevanten Informationen über ein Gerät,
/// die für die Authentifizierung und Identifikation bei der REST-API benötigt
/// werden.
class GsdDocuframeDevice {
  /// Erstellt eine neue GsdDocuframeDevice-Instanz
  ///
  /// [deviceId] - Eindeutige Geräte-ID (erforderlich)
  /// [device] - Anzeigename des Geräts (optional)
  /// [systemVersion] - Betriebssystemversion (optional)
  /// [fireBaseToken] - Firebase-Token (optional)
  /// [deviceType] - Gerätetyp (optional, Standard: unknown)
  /// [systemString] - Systembeschreibung (optional)
  GsdDocuframeDevice(
    this.deviceId, {
    this.device = '',
    this.systemVersion = '',
    this.fireBaseToken = '',
    this.deviceType = GsdDocuframeDeviceType.unkown,
    this.systemString = '',
  });

  /// Eindeutige Geräte-ID zur Identifizierung des Geräts
  ///
  /// Diese ID sollte für jedes Gerät eindeutig sein und wird verwendet,
  /// um das Gerät bei wiederholten Anmeldungen zu erkennen.
  final String deviceId;

  /// Anzeigename des Geräts (z.B. "iPhone 13", "Samsung Galaxy S21")
  final String device;

  /// Version des Betriebssystems (z.B. "iOS 15.0", "Android 12")
  final String systemVersion;

  /// Firebase-Token für Push-Benachrichtigungen
  ///
  /// Wird verwendet, um Push-Benachrichtigungen an das Gerät zu senden.
  final String fireBaseToken;

  /// Typ des Geräts (Android, iOS, Web, etc.)
  ///
  /// Standard ist "unknown" (0), wenn nicht anders angegeben.
  final GsdDocuframeDeviceType deviceType;

  /// Detaillierte Systembeschreibung
  ///
  /// Kann zusätzliche Informationen über das System enthalten.
  final String systemString;

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
  /// var device = GsdDocuframeDevice('device-123',
  ///   device: 'iPhone 13',
  ///   deviceType: GsdDocuframeDeviceType.ios
  /// );
  /// var json = device.toJson();
  /// print(json['deviceId']); // 'device-123'
  /// ```
  Map<String, dynamic> toJson() => {
    'deviceId': deviceId,
    'device': device,
    'systemVersion': systemVersion,
    'firebaseToken': fireBaseToken,
    'deviceType': deviceType.id.toString(),
    'systemType': deviceType.id.toString(),
    'systemString': systemString,
  };
}
