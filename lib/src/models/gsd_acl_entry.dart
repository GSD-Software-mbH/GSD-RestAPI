import 'package:equatable/equatable.dart';
import 'package:json_annotation/json_annotation.dart';

part 'gsd_acl_entry.g.dart';

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
@JsonSerializable(createToJson: false)
class GsdAclEntry extends Equatable {
  /// Erstellt eine neue GsdAclEntry-Instanz
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
  const GsdAclEntry({
    required this.oid,
    required this.status,
    required this.userName,
    required this.licenseKey,
    required this.licenseLevel,
    required this.parallelConnections,
    required this.tfaActivated,
    required this.tfaConfirmed,
    required this.application,
    required this.addOns,
    this.deviceID,
  });

  /// Erstellt eine GsdAclEntry-Instanz aus JSON-Daten
  factory GsdAclEntry.fromJson(Map<String, Object?> json) =>
      _$GsdAclEntryFromJson(json);

  /// Eindeutige Objekt-ID des ACL-Eintrags
  @JsonKey(name: 'Oid')
  final String oid;

  /// Status des ACL-Eintrags (z.B. 1 = aktiv)
  @JsonKey(name: 'Status')
  final int status;

  /// Benutzername für die Authentifizierung
  @JsonKey(name: 'UserName')
  final String userName;

  /// ID des zugeordneten Geräts (kann null sein)
  @JsonKey(name: 'DeviceID')
  final String? deviceID;

  /// Lizenzschlüssel für die Anwendung
  @JsonKey(name: 'LicenseKey')
  final String licenseKey;

  /// Lizenzlevel oder -typ
  @JsonKey(name: 'LicenseLevel')
  final String? licenseLevel;

  /// Anzahl der erlaubten parallelen Verbindungen
  @JsonKey(name: 'ParallelConnections')
  final double parallelConnections;

  /// Gibt an, ob Zwei-Faktor-Authentifizierung aktiviert ist
  @JsonKey(name: 'TFAActivated')
  final bool tfaActivated;

  /// Gibt an, ob Zwei-Faktor-Authentifizierung bestätigt wurde
  @JsonKey(name: 'TFAConfirmed')
  final bool tfaConfirmed;

  /// Name der zugeordneten Anwendung
  @JsonKey(name: 'Application')
  final String application;

  /// Add-Ons und Erweiterungen, aus `AddOns.~Elements`
  @JsonKey(readValue: _readAddOns, defaultValue: <String>[])
  final List<String> addOns;

  /// Konvertiert die GsdAclEntry-Instanz zu JSON-Daten
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

  @override
  List<Object?> get props => [
    oid,
    status,
    userName,
    deviceID,
    licenseKey,
    licenseLevel,
    parallelConnections,
    tfaActivated,
    tfaConfirmed,
    application,
    addOns,
  ];

  static Object? _readAddOns(Map<dynamic, dynamic> json, String key) =>
      switch (json['AddOns']) {
        {'~Elements': final Object? elements} => elements,
        _ => null,
      };
}
