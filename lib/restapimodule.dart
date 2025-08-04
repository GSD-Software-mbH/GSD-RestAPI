part of 'restapi.dart';

/// Repräsentiert ein Modul im REST-API-Service
/// 
/// Diese Klasse kapselt Informationen über ein verfügbares Modul
/// in einer REST-API-Datenbank, einschließlich Name und Version.
/// 
/// Module erweitern die Funktionalität der REST-API und haben
/// spezifische Versionsnummern für Kompatibilitätsprüfungen.
/// 
/// Wird verwendet für:
/// - Feature-Verfügbarkeit-Checks
/// - Versions-Kompatibilität zwischen Client und Server
/// - Funktions-spezifische API-Aufrufe
class RestApiModule {
  /// Name des Moduls
  /// 
  /// Eindeutige Identifikation des Moduls (z.B. "Core", "Email", "Calendar").
  String name;
  
  /// Version des Moduls
  /// 
  /// Versionsnummer im Format "x.y.z" für Kompatibilitätsprüfungen.
  String version;

  /// Erstellt eine neue RestApiModule-Instanz
  /// 
  /// [name] - Name des Moduls
  /// [version] - Versionsnummer des Moduls
  RestApiModule(this.name, this.version);
}