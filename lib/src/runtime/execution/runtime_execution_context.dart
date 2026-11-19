import 'dart:async';

import 'package:gsd_restapi/src/client/gsd_request_priority.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_policy.dart';
import 'package:meta/meta.dart';

@internal
final class RuntimeExecutionContext {
  const RuntimeExecutionContext._();
  static final Object _skipBufferingKey = Object();
  static final Object _priorityKey = Object();

  static bool get skipBuffering => Zone.current[_skipBufferingKey] == true;

  static GsdRequestPriority? get priority =>
      Zone.current[_priorityKey] as GsdRequestPriority?;

  /// Erfasst die aktuell aktiven Zone-Scopes als unveränderliche
  /// [RuntimeExecutionPolicy].
  ///
  /// Wird vom `ApiRuntime` GENAU EINMAL pro `execute`/
  /// `executeExternalTransport`-Aufruf aufgerufen, BEVOR jegliche
  /// Deduplizierung stattfindet - siehe [RuntimeExecutionPolicy]-Doku.
  /// Ohne aktiven Priority-Scope ist die effektive Priorität immer
  /// [GsdRequestPriority.normal].
  static RuntimeExecutionPolicy capture() {
    return RuntimeExecutionPolicy(
      skipBuffering: skipBuffering,
      priority: priority ?? GsdRequestPriority.normal,
    );
  }

  static Future<T> runWithoutBuffering<T>(Future<T> Function() action) {
    return runZoned(action, zoneValues: {_skipBufferingKey: true});
  }

  static Future<T> runWithPriority<T>(
    Future<T> Function() action,
    GsdRequestPriority priority,
  ) {
    return runZoned(action, zoneValues: {_priorityKey: priority});
  }
}
