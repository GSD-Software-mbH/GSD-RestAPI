part of 'gsd_restapi.dart';

/// Repräsentiert einen ACL (Access Control List) Eintrag im REST-API-Service
///
/// Diese Klasse kapselt Benutzer- und Lizenzinformationen für den Zugriff
/// auf den REST-API-Service, einschließlich Authentifizierung, Lizenzen
/// und Zwei-Faktor-Authentifizierung.
///
/// Wird verwendet von:
/// - Benutzerauthentifizierung und -autorisierung
/// - Lizenzvalidierung und -management
/// - Zwei-Faktor-Authentifizierung (TFA)
/// - Geräte- und Anwendungszuordnung
class RestApiACLEntry {
  /// Eindeutige Objekt-ID des ACL-Eintrags
  String oid;

  /// Status des ACL-Eintrags (z.B. 1 = aktiv)
  int status;

  /// Benutzername für die Authentifizierung
  String userName;

  /// ID des zugeordneten Geräts (kann null sein)
  String? deviceID;

  /// Lizenzschlüssel für die Anwendung
  String licenseKey;

  /// Lizenzlevel oder -typ
  String? licenseLevel;

  /// Anzahl der erlaubten parallelen Verbindungen
  double parallelConnections;

  /// Gibt an, ob Zwei-Faktor-Authentifizierung aktiviert ist
  bool tfaActivated;

  /// Gibt an, ob Zwei-Faktor-Authentifizierung bestätigt wurde
  bool tfaConfirmed;

  /// Name der zugeordneten Anwendung
  String application;

  /// Add-Ons und Erweiterungen
  List<String> addOns;

  /// Erstellt eine neue RestApiACLEntry-Instanz
  ///
  /// [oid] - Eindeutige Objekt-ID
  /// [status] - Status des Eintrags
  /// [userName] - Benutzername
  /// [deviceID] - Geräte-ID (optional)
  /// [licenseKey] - Lizenzschlüssel
  /// [licenseLevel] - Lizenzlevel
  /// [parallelConnections] - Anzahl paralleler Verbindungen
  /// [tfaActivated] - TFA aktiviert
  /// [tfaConfirmed] - TFA bestätigt
  /// [application] - Anwendungsname
  /// [addOns] - Add-Ons und Erweiterungen
  RestApiACLEntry({
    required this.oid,
    required this.status,
    required this.userName,
    this.deviceID,
    required this.licenseKey,
    required this.licenseLevel,
    required this.parallelConnections,
    required this.tfaActivated,
    required this.tfaConfirmed,
    required this.application,
    required this.addOns,
  });

  /// Erstellt eine RestApiACLEntry-Instanz aus JSON-Daten
  factory RestApiACLEntry.fromJson(Map<String, dynamic> json) {
    dynamic addOnsJson = json['AddOns']?['~Elements'] ?? [];

    List<String> addOnsList = [];

    if (addOnsJson is List) {
      addOnsList = List<String>.from(addOnsJson);
    }

    return RestApiACLEntry(
      oid: json['Oid'] as String,
      status: json['Status'] as int,
      userName: json['UserName'] as String,
      deviceID: json['DeviceID'] as String?,
      licenseKey: json['LicenseKey'] as String,
      licenseLevel: json['LicenseLevel'] as String?,
      parallelConnections: (json['ParallelConnections'] as num).toDouble(),
      tfaActivated: json['TFAActivated'] as bool,
      tfaConfirmed: json['TFAConfirmed'] as bool,
      application: json['Application'] as String,
      addOns: addOnsList,
    );
  }

  /// Konvertiert die RestApiACLEntry-Instanz zu JSON-Daten
  Map<String, dynamic> toJson() {
    return {
      'Oid': oid,
      'Status': status,
      'UserName': userName,
      'DeviceID': deviceID,
      'LicenseKey': licenseKey,
      'LicenseLevel': licenseLevel,
      'ParallelConnections': parallelConnections,
      'TFAActivated': tfaActivated,
      'TFAConfirmed': tfaConfirmed,
      'Application': application,
      'AddOns': {'~Count': addOns.length, '~Elements': addOns},
    };
  }
}
