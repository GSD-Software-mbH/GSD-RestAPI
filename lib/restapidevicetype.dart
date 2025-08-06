part of 'gsd_restapi.dart';

/// Enum für verschiedene Gerätetypen, die mit der REST-API interagieren können
/// 
/// Jeder Typ hat eine eindeutige ID, die bei der Kommunikation mit dem Server verwendet wird.
enum RestApiDeviceType {
  /// Unbekannter oder nicht spezifizierter Gerätetyp (ID: 0)
  unkown(0),
  
  /// Android-Geräte (ID: 100)
  android(100),
  
  /// iOS-Geräte (iPhone, iPad) (ID: 200)
  ios(200),
  
  /// Web-Browser (ID: 300)
  web(300);

  /// Die eindeutige ID des Gerätetyps, die an den Server gesendet wird
  final int id;

  /// Erstellt eine neue Instanz des Gerätetyps mit der angegebenen ID
  const RestApiDeviceType(this.id);
}