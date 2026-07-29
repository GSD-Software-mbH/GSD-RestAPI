import 'package:meta/meta.dart';

import '../policies/request_priority.dart';

/// Unveränderliche Momentaufnahme der Zone-gesteuerten Ausführungsrichtlinie
/// (siehe `RuntimeExecutionContext`).
///
/// `ApiRequest` beschreibt ausschließlich den fachlich-technischen
/// Endpunkt-Vertrag (Verb, Route, Query, Body, Header, Auth, Dedup,
/// Response-Policy, Operation-ID) und enthält WEDER eine Priorität NOCH eine
/// einstellbare Buffering-Policy. `ApiRuntime.execute`/
/// `executeExternalTransport` erfassen stattdessen GENAU EINMAL (über
/// `RuntimeExecutionContext.capture()`), BEVOR jegliche Deduplizierung
/// stattfindet, die zu diesem Zeitpunkt aktiven Zone-Scopes als
/// [RuntimeExecutionPolicy] und reichen sie als SEPARATEN Parameter durch
/// Dedup-Schlüssel-Berechnung, Session-Retry, Dispatch und Batch-Enqueue -
/// dadurch sehen Dedup-Schlüssel, Telemetrie und der physische Sendepfad
/// dieselben Werte, und ein Session-Refresh-Retry behält die ursprünglich
/// erfasste Policy bei, statt sie erneut aus der (ggf. inzwischen anderen)
/// Zone zu lesen.
@internal
final class RuntimeExecutionPolicy {
  /// Ob Buffering für diese Ausführung vollständig deaktiviert ist
  /// (`RuntimeExecutionContext.runWithoutBuffering`). Gewinnt IMMER gegenüber
  /// [priority] - auch gegenüber [ApiRequestPriority.high] wäre das
  /// gleichbedeutend, da `high` ohnehin nie puffert.
  final bool skipBuffering;

  /// Effektive interne Priorität gegenüber dem Multi-Request-Buffering des
  /// `BatchCoordinator`. Ohne aktiven Priority-Scope
  /// (`RuntimeExecutionContext.runWithPriority`) immer
  /// [ApiRequestPriority.normal] - Endpunkte können nie ihre eigene
  /// Priorität vorgeben.
  final ApiRequestPriority priority;

  const RuntimeExecutionPolicy({
    required this.skipBuffering,
    required this.priority,
  });

  @override
  String toString() =>
      'RuntimeExecutionPolicy(skipBuffering: $skipBuffering, '
      'priority: $priority)';
}
