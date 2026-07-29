import 'package:meta/meta.dart';

/// Hält den veränderlichen Session-Zustand getrennt von der kontrollierten
/// `RuntimeConfiguration`.
/// Diese Klasse ist bewusst ein einfacher, änderungsbenachrichtigender
/// Zustandshalter für den `SessionCoordinator`.
@internal
class SessionState {
  String _sessionId;

  /// Optionaler Hook, der bei jeder tatsächlichen Änderung der Session-ID
  /// aufgerufen wird (nur bei Wertänderung, nicht bei erneuter Zuweisung
  /// desselben Werts). Wird vom `SessionCoordinator` genutzt, um
  /// z.B. `RestApiDOCUframeCallbacks.onSessionIdChanged` weiterzureichen.
  void Function(String sessionId)? onSessionIdChanged;

  SessionState([this._sessionId = '']);

  /// Aktuelle Session-ID; leer, solange keine Anmeldung erfolgt ist.
  String get sessionId => _sessionId;

  set sessionId(String value) {
    if (_sessionId == value) {
      return;
    }

    _sessionId = value;
    onSessionIdChanged?.call(value);
  }
}
