import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_context.dart';
import 'package:gsd_restapi/src/runtime/execution/runtime_execution_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/request_priority.dart';

void main() {
  test('capture uses normal priority when no Zone scope is active', () {
    final policy = RuntimeExecutionContext.capture();

    expect(policy.skipBuffering, isFalse);
    expect(policy.priority, ApiRequestPriority.normal);
  });

  test('capture returns an immutable snapshot of the active scopes', () async {
    late final RuntimeExecutionPolicy captured;

    await RuntimeExecutionContext.runWithoutBuffering(() async {
      await RuntimeExecutionContext.runWithPriority(() async {
        captured = RuntimeExecutionContext.capture();
      }, RequestPriority.low);
    });

    expect(captured.skipBuffering, isTrue);
    expect(captured.priority, ApiRequestPriority.low);
    expect(RuntimeExecutionContext.capture().skipBuffering, isFalse);
    expect(
      RuntimeExecutionContext.capture().priority,
      ApiRequestPriority.normal,
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
        expect(RuntimeExecutionContext.priority, RequestPriority.low);
        await RuntimeExecutionContext.runWithPriority(() async {
          expect(RuntimeExecutionContext.priority, RequestPriority.high);
        }, RequestPriority.high);
        expect(RuntimeExecutionContext.priority, RequestPriority.low);
      }, RequestPriority.low);
    },
  );

  test('withoutBuffering remains active through nested priority scopes and '
      'restores outer values', () async {
    expect(RuntimeExecutionContext.skipBuffering, isFalse);
    expect(RuntimeExecutionContext.priority, isNull);

    await RuntimeExecutionContext.runWithPriority(() async {
      expect(RuntimeExecutionContext.skipBuffering, isFalse);
      expect(RuntimeExecutionContext.priority, RequestPriority.low);

      await RuntimeExecutionContext.runWithoutBuffering(() async {
        expect(RuntimeExecutionContext.skipBuffering, isTrue);
        expect(RuntimeExecutionContext.priority, RequestPriority.low);

        await RuntimeExecutionContext.runWithPriority(() async {
          await Future<void>.delayed(Duration.zero);
          expect(RuntimeExecutionContext.skipBuffering, isTrue);
          expect(RuntimeExecutionContext.priority, RequestPriority.high);
        }, RequestPriority.high);

        expect(RuntimeExecutionContext.skipBuffering, isTrue);
        expect(RuntimeExecutionContext.priority, RequestPriority.low);
      });

      expect(RuntimeExecutionContext.skipBuffering, isFalse);
      expect(RuntimeExecutionContext.priority, RequestPriority.low);
    }, RequestPriority.low);

    expect(RuntimeExecutionContext.skipBuffering, isFalse);
    expect(RuntimeExecutionContext.priority, isNull);
  });

  test('parallel scopes do not leak priority', () async {
    final lowSeen = Completer<RequestPriority?>();
    final highSeen = Completer<RequestPriority?>();

    await Future.wait([
      RuntimeExecutionContext.runWithPriority(() async {
        await Future<void>.delayed(const Duration(milliseconds: 5));
        lowSeen.complete(RuntimeExecutionContext.priority);
      }, RequestPriority.low),
      RuntimeExecutionContext.runWithPriority(() async {
        highSeen.complete(RuntimeExecutionContext.priority);
      }, RequestPriority.high),
    ]);

    expect(await lowSeen.future, RequestPriority.low);
    expect(await highSeen.future, RequestPriority.high);
    expect(RuntimeExecutionContext.priority, isNull);
  });
}
