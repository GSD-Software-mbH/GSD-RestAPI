import 'package:meta/meta.dart';

/// Legt fest, ob nebenläufige, technisch identische Requests eine gemeinsame
/// Ausführung teilen dürfen.
///
/// Deduplizierung ist standardmäßig deaktiviert, weil insbesondere schreibende
/// Requests trotz identischem Inhalt jeweils eine eigene Serveraktion
/// darstellen können. Endpoints dürfen sie nur dann explizit aktivieren, wenn
/// ihre Operation idempotent ist und ein geteiltes Ergebnis fachlich korrekt
/// bleibt.
@internal
enum DeduplicationPolicy {
  /// Jeder Aufruf wird unabhängig ausgeführt.
  disabled,

  /// Nebenläufige, technisch identische Aufrufe teilen eine Ausführung.
  ///
  /// WICHTIG: Der `ApiRuntime`-Dedup-Schlüssel vergleicht die verwendete
  /// `ResponsePolicy` per IDENTITÄT, nicht per Wert (siehe `_RequestDedupKey`
  /// in `api_runtime.dart`). Konstruiert ein Endpunkt pro Aufruf eine neue,
  /// nicht `const`/nicht gecachte `ResponsePolicy`-Instanz, bleibt `enabled`
  /// wirkungslos - ohne sichtbaren Fehler. Endpunkte müssen daher eine
  /// stabile (z.B. `const`) `ResponsePolicy`-Instanz verwenden, damit Dedup
  /// tatsächlich greift.
  enabled,
}
