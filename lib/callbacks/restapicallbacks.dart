part of '../gsd_restapi.dart';

/// Basis-Callback-Management-System für REST-API-Events
///
/// Diese Basisklasse verwaltet grundlegende Callback-Funktionen für REST-API-Events:
/// - Log- und Debug-Events für Monitoring und Fehlerdiagnose
/// - HTTP-Metriken und Performance-Events für Analyse
///
/// Die Klasse bietet eine zentrale Verwaltung für Event-Handler und dient als
/// Basisklasse für spezialisierte Callback-Systeme wie RestApiDOCUframeCallbacks.
///
/// Vorteile:
/// - Zentrale Verwaltung grundlegender Event-Handler
/// - Typ-sichere Callback-Definitionen
/// - Einfache Event-Registrierung und -Verwaltung
/// - Bessere Testbarkeit durch isolierte Event-Logik
/// - Erweiterbar für spezielle Anwendungsfälle
class RestApiCallbacks {
  /// Callback-Funktion für Log-Nachrichten
  ///
  /// Diese optionale Callback-Funktion wird aufgerufen, um Log-Nachrichten
  /// und Debug-Informationen an die aufrufende Anwendung weiterzugeben.
  ///
  /// Die Funktion erhält eine String-Nachricht mit Informationen über:
  /// - HTTP-Anfrage-URIs und -Header
  /// - Request- und Response-Bodies (gekürzt bei großen Inhalten)
  /// - Upload-Status und -Fortschritt
  /// - Fehler- und Debug-Meldungen
  ///
  /// Parameter: [message] - Die Log-Nachricht als String
  ///
  /// Beispiel-Implementierung:
  /// ```dart
  /// callbacks.onLogMessage = (String message) async {
  ///   print("RestAPI Log: $message");
  ///   // oder in Datei schreiben, an externes Logging-System senden, etc.
  /// };
  /// ```
  Future<void> Function(String message)? onLogMessage;

  /// Callback-Funktion für HTTP-Metriken
  ///
  /// Diese optionale Callback-Funktion wird aufgerufen, wenn HTTP-Anfragen
  /// abgeschlossen sind und Performance-Metriken verfügbar sind.
  ///
  /// Die Metriken enthalten Informationen über:
  /// - Anfrage-Dauer und Timing
  /// - Request-/Response-Größen
  /// - Erfolg/Fehler-Status
  /// - API-Endpunkt-Details
  ///
  /// Parameter: [metric] - Die RestApiHttpMetric mit Performance-Daten
  ///
  /// Beispiel-Implementierung:
  /// ```dart
  /// callbacks.onHttpMetricRecorded = (RestApiHttpMetric metric) async {
  ///   print("API-Aufruf: ${metric.function} - ${metric.duration}ms");
  ///   // Metriken an Analytics-System senden
  ///   analytics.recordApiCall(metric);
  /// };
  /// ```
  Future<void> Function(RestApiHttpMetric metric)? onHttpMetricRecorded;

  /// Erstellt ein neues RestApiCallbacks-System
  RestApiCallbacks({this.onLogMessage, this.onHttpMetricRecorded});

  /// **Event-Trigger-Methoden (für interne Verwendung)**

  /// Löst das Log-Event aus
  ///
  /// Ruft den onLogMessage-Callback auf, falls gesetzt.
  /// Fängt Exceptions ab, um das Hauptprogramm nicht zu beeinträchtigen.
  ///
  /// [message] - Die zu loggende Nachricht
  Future<void> triggerLogEvent(String message) async {
    await onLogMessage?.call(message);
  }

  /// Löst das HTTP-Metric-Recorded-Event aus
  ///
  /// [metric] - Die HTTP-Metriken
  Future<void> triggerHttpMetricRecordedEvent(RestApiHttpMetric metric) async {
    await onHttpMetricRecorded?.call(metric);
  }

  /// Entfernt alle Callbacks
  void clearAllCallbacks() {
    onLogMessage = null;
    onHttpMetricRecorded = null;
  }
}
