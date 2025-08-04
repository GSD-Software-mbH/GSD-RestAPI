part of '../restapi.dart';

/// Exception für Sicherheitsverletzungen
/// 
/// Wird geworfen, wenn eine Aktion aus Sicherheitsgründen blockiert wird.
/// Typische Verwendungsfälle:
/// - Unverschlüsselte HTTP-Verbindungen in Production
/// - Unsichere SSL-Zertifikate
/// - Blockierte Protokolle oder Domains
/// - Sicherheitsrichtlinien-Verletzungen
class SecurityException implements Exception {
  /// Beschreibende Fehlernachricht über die Sicherheitsverletzung
  final String message;
  
  /// Erstellt eine neue SecurityException
  /// 
  /// [message] - Beschreibung der Sicherheitsverletzung
  SecurityException(this.message);
  
  /// String-Darstellung der Exception
  @override
  String toString() => 'SecurityException: $message';
}