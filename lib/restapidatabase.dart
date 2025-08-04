part of 'restapi.dart';

/// Repräsentiert eine Datenbank im REST-API-Service
/// 
/// Diese Klasse kapselt Informationen über eine verfügbare Datenbank
/// im REST-API-Service, einschließlich der installierten Module und
/// deren Versionen.
/// 
/// Wird verwendet von:
/// - RestApiCheckServiceResponse zur Service-Status-Überprüfung
/// - Kompatibilitätsprüfungen zwischen Client und Server
/// - Modul-Versions-Management
class RestApiDatabase {
  /// Name/Alias der Datenbank
  /// 
  /// Eindeutige Identifikation der Datenbank, wird in API-Aufrufen
  /// als Pfad-Parameter verwendet (z.B. "/dbname/v1/login").
  String name;
  
  /// Liste der in dieser Datenbank verfügbaren Module
  /// 
  /// Jedes Modul enthält Name und Versionsinformationen,
  /// die für Funktionskompatibilität wichtig sind.
  List<RestApiModule> modules;

  /// Erstellt eine neue RestApiDatabase-Instanz
  /// 
  /// [name] - Name/Alias der Datenbank
  /// [modules] - Liste der verfügbaren Module
  RestApiDatabase(this.name, this.modules);
}