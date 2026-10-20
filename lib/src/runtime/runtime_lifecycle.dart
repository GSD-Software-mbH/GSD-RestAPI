import 'package:meta/meta.dart';

/// Vertrag für idempotentes Aufräumen von Runtime-Ressourcen (HTTP-Client,
/// Timer, Uploads, ...).
///
/// `dispose()` darf beliebig oft aufgerufen werden; nur der erste Aufruf
/// gibt tatsächlich Ressourcen frei, alle weiteren Aufrufe sind No-Ops.
/// Nach `dispose()` schlagen weitere fachliche Operationen mit einem
/// [StateError] fehl.
@internal
abstract interface class RuntimeLifecycle {
  /// Gibt Ressourcen frei. Idempotent: mehrfacher Aufruf ist sicher.
  Future<void> dispose();
}
