import 'package:meta/meta.dart';

/// Dedupliziert nebenläufige, inhaltsgleiche Aktionen: Läuft für einen
/// Schlüssel bereits eine Aktion, teilen sich alle weiteren Aufrufer mit
/// demselben Schlüssel EIN Future statt selbst erneut auszuführen.
///
/// Reproduziert die Grundidee von
/// `RestApiDOCUframeManager._performRequest` (Pending-Requests, dort nach
/// `md5("uri|headers|body")` geschlüsselt), aber ECHT: Die Task-1-
/// Charakterisierung hat gezeigt, dass der Legacy-Dedup NICHT griff - jede
/// `RestApiRequest.execute()` baute und sendete ihre eigene Anfrage, die
/// Pending-Map wurde nie tatsächlich abgefragt, sondern nur befüllt und
/// wieder geleert. Hier teilen sich nebenläufige, schlüsselgleiche
/// Aufrufer garantiert EINE Ausführung UND ein Ergebnis (Erfolg wie
/// Fehler).
///
/// Verhalten:
/// - Läuft für [key] noch keine Aktion, wird `action` aufgerufen und deren
///   Future unter [key] gemerkt.
/// - Läuft für [key] bereits eine Aktion, wird DASSELBE (geteilte) Future
///   zurückgegeben statt `action` erneut aufzurufen.
/// - Nach Abschluss - Erfolg ODER Fehler - wird [key] entfernt (`whenComplete`):
///   ein nachfolgender, NICHT überlappender Aufruf mit demselben Schlüssel
///   führt `action` erneut aus.
/// - Fehler propagieren unverändert an ALLE Aufrufer, die sich das Future
///   geteilt haben.
///
/// Schlüsselwahl obliegt bewusst dem Aufrufer
/// (`ApiRuntime`); dieser Koordinator kennt keine `ApiRequest`-Struktur und
/// bleibt dadurch unabhängig wiederverwendbar.
@internal
class RequestCoordinator {
  /// Futures aktuell laufender Aktionen, geschlüsselt nach ihrem
  /// Dedup-Schlüssel. `dynamic` statt eines festen Typs, da pro Aufruf ein
  /// anderer generischer Ergebnistyp möglich ist; [deduplicate] castet beim
  /// Zurückgeben entsprechend auf `Future<T>`.
  final Map<Object, Future<dynamic>> _pending = {};

  /// Führt `action` aus - oder teilt, falls für [key] bereits eine Aktion
  /// läuft, deren Ergebnis (Erfolg wie Fehler).
  Future<T> deduplicate<T>(Object key, Future<T> Function() action) {
    final Future<dynamic>? existing = _pending[key];
    if (existing != null) {
      return existing as Future<T>;
    }

    return _pending[key] = Future<T>.sync(action).whenComplete(() {
      _pending.remove(key);
    });
  }
}
