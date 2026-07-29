import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi_example/main.dart';

void main() {
  test('Neue API verwendet vorhandene native Endpoints statt RawApi', () {
    final String source = File('lib/main.dart').readAsStringSync();

    expect(source, isNot(contains('_modernApi!.raw')));
    expect(source, isNot(contains('RawApiResponse')));
  });

  testWidgets(
    'switches between Legacy and the new API without changing layout',
    (WidgetTester tester) async {
      await tester.pumpWidget(const MyApp());

      expect(
        find.text('RestApiDOCUframeManager konfigurieren'),
        findsOneWidget,
      );
      expect(find.text('Architecture: Legacy'), findsOneWidget);
      expect(find.text('Actions'), findsOneWidget);
      expect(find.text('Activity Log'), findsOneWidget);
      expect(
        find.widgetWithText(ElevatedButton, 'Test Multi-Request (10 Seiten)'),
        findsOneWidget,
      );

      await tester.tap(find.text('Neue API'));
      await tester.pumpAndSettle();

      expect(find.text('DOCUframeApi konfigurieren'), findsOneWidget);
      expect(find.text('Architecture: Neue API'), findsOneWidget);
      expect(find.text('Actions'), findsOneWidget);
      expect(find.text('Native V2 Endpoints'), findsOneWidget);
      expect(find.text('Bodylose Endpoints'), findsOneWidget);
      expect(find.text('Endpoints mit JSON Body'), findsOneWidget);
      expect(
        find.widgetWithText(ElevatedButton, 'v2.model.structure'),
        findsOneWidget,
      );
      expect(
        find.widgetWithText(ElevatedButton, 'v2.system.versionInfo'),
        findsOneWidget,
      );
      expect(
        find.widgetWithText(ElevatedButton, 'v2.objectData.getById'),
        findsOneWidget,
      );
      expect(
        find.widgetWithText(OutlinedButton, 'objectData.getById Vorlage'),
        findsOneWidget,
      );
      expect(find.text('JSON Body (optional)'), findsOneWidget);
      expect(find.text('Letzte V2 Response'), findsOneWidget);
      expect(find.text('Datei-Download (v2/file)'), findsOneWidget);
      expect(find.text('Activity Log'), findsOneWidget);

      // Die Datei-Parameter sind alle optional: kein Feld ist vorbelegt und
      // usePdf steht auf "nicht senden", damit die URL ohne Zutun genau
      // v2/file/{oid} lautet.
      for (final String fieldKey in <String>[
        'v2-file-oid-field',
        'v2-file-page-field',
        'v2-file-attach-item-field',
        'v2-file-zip-item-field',
        'v2-file-max-size-field',
      ]) {
        final TextField field = tester.widget<TextField>(
          find.byKey(ValueKey<String>(fieldKey)),
        );
        expect(field.controller!.text, isEmpty, reason: fieldKey);
      }
      final DropdownButtonFormField<bool?> usePdfField = tester
          .widget<DropdownButtonFormField<bool?>>(
            find.byKey(const ValueKey<String>('v2-file-use-pdf-field')),
          );
      expect(usePdfField.initialValue, isNull);

      final Finder byIdTemplate = find.byKey(
        const ValueKey<String>('v2-template-objectDataById'),
      );
      await tester.ensureVisible(byIdTemplate);
      await tester.tap(byIdTemplate);
      await tester.pumpAndSettle();

      final TextField bodyField = tester.widget<TextField>(
        find.byKey(const ValueKey<String>('v2-body-field')),
      );
      final dynamic byIdBody = jsonDecode(bodyField.controller!.text);
      expect(byIdBody, <dynamic>[
        <String, dynamic>{
          'classId': 100,
          'type': '',
          'context': 'edit',
          'ids': <dynamic>[200, 201],
        },
      ]);

      final ElevatedButton checkServiceButton = tester.widget<ElevatedButton>(
        find.widgetWithText(ElevatedButton, 'Check Service'),
      );
      final ElevatedButton checkSessionButton = tester.widget<ElevatedButton>(
        find.widgetWithText(ElevatedButton, 'Check Session'),
      );
      expect(checkServiceButton.onPressed, isNull);
      expect(checkSessionButton.onPressed, isNull);

      final ElevatedButton v2Button = tester.widget<ElevatedButton>(
        find.widgetWithText(ElevatedButton, 'v2.model.structure'),
      );
      expect(v2Button.onPressed, isNull);

      final ElevatedButton fileButton = tester.widget<ElevatedButton>(
        find.byKey(const ValueKey<String>('v2-file-get-button')),
      );
      expect(fileButton.onPressed, isNull);

      final Finder configureButton = find.text('DOCUframe konfigurieren');
      await tester.ensureVisible(configureButton);
      await tester.pumpAndSettle();
      await tester.tap(configureButton);
      await tester.pumpAndSettle();

      final ElevatedButton configuredServiceButton = tester
          .widget<ElevatedButton>(
            find.widgetWithText(ElevatedButton, 'Check Service'),
          );
      final ElevatedButton configuredSessionButton = tester
          .widget<ElevatedButton>(
            find.widgetWithText(ElevatedButton, 'Check Session'),
          );
      expect(configuredServiceButton.onPressed, isNotNull);
      expect(configuredSessionButton.onPressed, isNull);
    },
  );
}
