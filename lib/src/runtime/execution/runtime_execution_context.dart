import 'dart:async';

import 'package:meta/meta.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

import '../policies/request_priority.dart';
import 'runtime_execution_policy.dart';

@internal
final class RuntimeExecutionContext {
  static final Object _skipBufferingKey = Object();
  static final Object _priorityKey = Object();

  const RuntimeExecutionContext._();

  static bool get skipBuffering => Zone.current[_skipBufferingKey] == true;

  static RequestPriority? get priority =>
      Zone.current[_priorityKey] as RequestPriority?;

  /// Erfasst die aktuell aktiven Zone-Scopes als unveränderliche
  /// [RuntimeExecutionPolicy].
  ///
  /// Wird vom `ApiRuntime` GENAU EINMAL pro `execute`/
  /// `executeExternalTransport`-Aufruf aufgerufen, BEVOR jegliche
  /// Deduplizierung stattfindet - siehe [RuntimeExecutionPolicy]-Doku.
  /// Ohne aktiven Priority-Scope ist die effektive Priorität immer
  /// [ApiRequestPriority.normal].
  static RuntimeExecutionPolicy capture() {
    final ApiRequestPriority effectivePriority = switch (priority) {
      RequestPriority.low => ApiRequestPriority.low,
      RequestPriority.normal => ApiRequestPriority.normal,
      RequestPriority.high => ApiRequestPriority.high,
      null => ApiRequestPriority.normal,
    };

    return RuntimeExecutionPolicy(
      skipBuffering: skipBuffering,
      priority: effectivePriority,
    );
  }

  static Future<T> runWithoutBuffering<T>(Future<T> Function() action) {
    return runZoned(action, zoneValues: {_skipBufferingKey: true});
  }

  static Future<T> runWithPriority<T>(
    Future<T> Function() action,
    RequestPriority priority,
  ) {
    return runZoned(action, zoneValues: {_priorityKey: priority});
  }
}
