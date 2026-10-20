import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('neuer Runtime enthält keine Fallbacks auf Legacy-Ausführungswege', () {
    final runtimeDirectory = Directory('lib/src/runtime');
    final forbiddenImports = <String>[
      'legacy/restapidocuframemanager.dart',
      'legacy/restapirequest.dart',
      'legacy/restapibufferedrequest.dart',
      'shared/restapifileuploadcontroller.dart',
      'shared/restapiuploadfile.dart',
    ];
    final forbiddenCalls = <RegExp>[
      RegExp(r'\bRestApiDOCUframeManager\s*[.(]'),
      RegExp(r'\bRestApiRequest\s*[<(]'),
      RegExp(r'\bRestAPIBufferedRequest\s*[<(]'),
      RegExp(r'\bcustomRequest\s*\('),
    ];

    final violations = <String>[];
    for (final entity in runtimeDirectory.listSync(recursive: true)) {
      if (entity is! File || !entity.path.endsWith('.dart')) {
        continue;
      }

      final source = entity.readAsStringSync();
      final importLines = source
          .split('\n')
          .map((line) => line.trim())
          .where((line) => line.startsWith('import '));
      for (final importLine in importLines) {
        for (final forbiddenImport in forbiddenImports) {
          if (importLine.toLowerCase().contains(forbiddenImport)) {
            violations.add('${entity.path}: $importLine');
          }
        }
      }

      final sourceWithoutComments = source
          .replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '')
          .replaceAll(RegExp(r'//.*'), '');
      for (final forbiddenCall in forbiddenCalls) {
        if (forbiddenCall.hasMatch(sourceWithoutComments)) {
          violations.add('${entity.path}: ${forbiddenCall.pattern}');
        }
      }
    }

    expect(
      violations,
      isEmpty,
      reason: 'Die neue Runtime darf keine Legacy-Ausführungswege verwenden.',
    );
  });
}
