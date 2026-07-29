import 'package:meta/meta.dart';

/// Legt fest, wie ein Request gegenüber der DOCUframe-API authentifiziert
/// wird.
@internal
enum AuthenticationPolicy {
  /// Keine Session-Authentifizierung: Es wird kein `sessionid`-Header
  /// gesetzt (z.B. für Login- oder Service-Check-Endpunkte).
  none,

  /// Session-Authentifizierung: Der `sessionid`-Header wird gesetzt, sofern
  /// im `SessionState` eine nicht-leere Session-ID vorliegt. Bei
  /// Session-Fehlern (`201`/`204`) versucht der `ApiRuntime` - sofern ein
  /// `SessionCoordinator` angebunden ist - genau einen Session-Refresh mit
  /// anschließendem Retry.
  session,

  /// Wie [session] (Session-Header wird gesetzt), aber eine ungültige
  /// Session löst KEINEN automatischen Refresh/Retry aus. Wird z.B. für
  /// den Logout verwendet: Ein bereits abgelaufener Logout darf keinen
  /// Re-Login auslösen.
  sessionNoRefresh,
}
