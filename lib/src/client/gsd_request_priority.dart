/// Enum für Request-Prioritäten
///
/// Definiert die verschiedenen Prioritätsstufen für API-Requests.
/// Beeinflusst die Verarbeitung und das Buffering von Multi-Requests.
enum GsdRequestPriority {
  /// Niedrige Priorität - Hintergrund-Operationen, längeres Buffering
  low,

  /// Normale Priorität - Standard-Requests, normales Buffering
  normal,

  /// Hohe Priorität - Sofortige Verarbeitung, kein Buffering: auch ein
  /// sonst Multi-Request-fähiger Aufruf geht sofort als Einzelanfrage.
  high,
}
