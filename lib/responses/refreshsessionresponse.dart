part of '../restapi.dart';

/// Response-Klasse für Session-Erneuerungs-Operationen
/// 
/// Diese Klasse kapselt das Ergebnis einer automatischen Session-Erneuerung,
/// die intern vom RestApiManager durchgeführt wird, wenn eine Session
/// abgelaufen oder ungültig geworden ist.
/// 
/// Enthält Informationen über:
/// - Erfolgsstatus der Session-Erneuerung
/// - Anzahl der Wiederholungsversuche
/// - Neue Session-ID bei Erfolg
/// - Fehlermeldungen bei Problemen
class RefreshSessionResponse {
  /// Getter für den Aktivitätsstatus der Session
  /// 
  /// Returns: true wenn Session erfolgreich erneuert wurde, sonst false
  get isActive => _isActive;

  /// Maximale Anzahl der erlaubten Wiederholungsversuche
  /// 
  /// Wird vom RestApiManager konfiguriert (Standard: 3).
  int maxRetryCount;
  
  /// Tatsächliche Anzahl der durchgeführten Wiederholungsversuche
  /// 
  /// Zeigt an, wie viele Versuche für die Session-Erneuerung benötigt wurden.
  int retryCount;
  
  /// Optionale Nachricht über den Session-Erneuerungs-Prozess
  /// 
  /// Kann Fehlermeldungen oder Statusinformationen enthalten.
  String message;
  
  /// Die neue Session-ID nach erfolgreicher Erneuerung
  /// 
  /// Wird für alle weiteren API-Aufrufe verwendet. Leer bei Fehlschlag.
  String sessionId;

  /// Interner Aktivitätsstatus der Session
  final bool _isActive;

  /// Erstellt eine neue RefreshSessionResponse-Instanz
  /// 
  /// [_isActive] - Ob die Session erfolgreich erneuert wurde
  /// [retryCount] - Anzahl der durchgeführten Versuche (Standard: 0)
  /// [maxRetryCount] - Maximale Anzahl erlaubter Versuche (Standard: 0)
  /// [message] - Optionale Statusnachricht (Standard: "")
  /// [sessionId] - Neue Session-ID bei Erfolg (Standard: "")
  RefreshSessionResponse(this._isActive,
      {this.retryCount = 0,
      this.maxRetryCount = 0,
      this.message = "",
      this.sessionId = ""});
}
