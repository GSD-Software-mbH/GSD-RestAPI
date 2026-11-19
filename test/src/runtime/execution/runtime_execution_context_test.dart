import 'dart:async';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/client/gsd_request_priority.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_context.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_policy.dart';
import 'package:test/test.dart';

void main() {
  test('capture uses normal priority when no Zone scope is active', () {
    final policy = RuntimeExecutionContext.capture();

    expect(policy.skipBuffering, isFalse);
    expect(policy.priority, GsdRequestPriority.normal);
  });

  test('capture returns an immutable snapshot of the active scopes', () async {
    late final RuntimeExecutionPolicy captured;

    await RuntimeExecutionContext.runWithoutBuffering(() async {
      await RuntimeExecutionContext.runWithPriority(() async {
        captured = RuntimeExecutionContext.capture();
      }, GsdRequestPriority.low);
    });

    expect(captured.skipBuffering, isTrue);
    expect(captured.priority, GsdRequestPriority.low);
    expect(RuntimeExecutionContext.capture().skipBuffering, isFalse);
    expect(
      RuntimeExecutionContext.capture().priority,
      GsdRequestPriority.normal,
    );
  });

  test('withoutBuffering survives an asynchronous gap', () async {
    expect(RuntimeExecutionContext.skipBuffering, isFalse);

    await RuntimeExecutionContext.runWithoutBuffering(() async {
      await Future<void>.delayed(Duration.zero);
      expect(RuntimeExecutionContext.skipBuffering, isTrue);
    });

    expect(RuntimeExecutionContext.skipBuffering, isFalse);
  });

  test(
    'inner priority overrides outer priority and then restores it',
    () async {
      await RuntimeExecutionContext.runWithPriority(() async {
        expect(RuntimeExecutionContext.priority, GsdRequestPriority.low);
        await RuntimeExecutionContext.runWithPriority(() async {
          expect(RuntimeExecutionContext.priority, GsdRequestPriority.high);
        }, GsdRequestPriority.high);
        expect(RuntimeExecutionContext.priority, GsdRequestPriority.low);
      }, GsdRequestPriority.low);
    },
  );

  test('withoutBuffering remains active through nested priority scopes and '
      'restores outer values', () async {
    expect(RuntimeExecutionContext.skipBuffering, isFalse);
    expect(RuntimeExecutionContext.priority, isNull);

    await RuntimeExecutionContext.runWithPriority(() async {
      expect(RuntimeExecutionContext.skipBuffering, isFalse);
      expect(RuntimeExecutionContext.priority, GsdRequestPriority.low);

      await RuntimeExecutionContext.runWithoutBuffering(() async {
        expect(RuntimeExecutionContext.skipBuffering, isTrue);
        expect(RuntimeExecutionContext.priority, GsdRequestPriority.low);

        await RuntimeExecutionContext.runWithPriority(() async {
          await Future<void>.delayed(Duration.zero);
          expect(RuntimeExecutionContext.skipBuffering, isTrue);
          expect(RuntimeExecutionContext.priority, GsdRequestPriority.high);
        }, GsdRequestPriority.high);

        expect(RuntimeExecutionContext.skipBuffering, isTrue);
        expect(RuntimeExecutionContext.priority, GsdRequestPriority.low);
      });

      expect(RuntimeExecutionContext.skipBuffering, isFalse);
      expect(RuntimeExecutionContext.priority, GsdRequestPriority.low);
    }, GsdRequestPriority.low);

    expect(RuntimeExecutionContext.skipBuffering, isFalse);
    expect(RuntimeExecutionContext.priority, isNull);
  });

  test('parallel scopes do not leak priority', () async {
    final lowSeen = Completer<GsdRequestPriority?>();
    final highSeen = Completer<GsdRequestPriority?>();

    await Future.wait([
      RuntimeExecutionContext.runWithPriority(() async {
        await Future<void>.delayed(const Duration(milliseconds: 5));
        lowSeen.complete(RuntimeExecutionContext.priority);
      }, GsdRequestPriority.low),
      RuntimeExecutionContext.runWithPriority(() async {
        highSeen.complete(RuntimeExecutionContext.priority);
      }, GsdRequestPriority.high),
    ]);

    expect(await lowSeen.future, GsdRequestPriority.low);
    expect(await highSeen.future, GsdRequestPriority.high);
    expect(RuntimeExecutionContext.priority, isNull);
  });
}
