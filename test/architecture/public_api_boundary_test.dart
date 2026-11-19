@TestOn('vm')
library;

import 'dart:io';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

/// Ordner unter `lib/src/`, deren Dateien das Barrel exportieren darf.
const _exportableDirectories = <String>{
  'client',
  'exceptions',
  'models',
  'raw',
  'v1',
  'v3',
};

final _typeDeclaration = RegExp(
  r'^(?:@\w+\s+)?(?:abstract |final |sealed |base |interface |mixin )*'
  r'(?:class|enum|mixin|extension|typedef) ([A-Za-z]\w*)',
  multiLine: true,
);

Future<void> _compileExecutionScopeCalls(GsdApiClient api) async {
  await api.executeWithoutBuffering(() async => 1);
  await api.executeWithPriority(() async => 1, GsdRequestPriority.low);
}

List<String> _barrelExports() {
  final source = File('lib/gsd_restapi.dart').readAsStringSync();
  return RegExp(
    "^export '([^']+)';",
    multiLine: true,
  ).allMatches(source).map((match) => match.group(1)!).toList();
}

String _exportedFilePath(String export) =>
    'lib/${export.replaceFirst('package:gsd_restapi/', '')}';

Iterable<File> _dartFiles(String directory) => Directory(directory)
    .listSync(recursive: true)
    .whereType<File>()
    .where((file) => file.path.endsWith('.dart'));

void main() {
  test('genau ein Barrel unter lib/', () {
    final topLevel = Directory('lib')
        .listSync()
        .whereType<File>()
        .where((file) => file.path.endsWith('.dart'))
        .map((file) => file.uri.pathSegments.last);

    expect(topLevel, equals(['gsd_restapi.dart']));
  });

  test('Barrel exportiert nur src-Dateien aus der Allowlist', () {
    final exports = _barrelExports();

    expect(exports, isNotEmpty);
    for (final export in exports) {
      expect(
        export,
        startsWith('package:gsd_restapi/src/'),
        reason: export,
      );
      final segments = export
          .replaceFirst('package:gsd_restapi/src/', '')
          .split('/');
      // Ordner aus der Allowlist, darin höchstens ein Unterordner
      // (`models/v3/`).
      expect(segments.length, inInclusiveRange(2, 3), reason: export);
      expect(_exportableDirectories, contains(segments.first), reason: export);
      expect(File(_exportedFilePath(export)).existsSync(), isTrue);
    }
  });

  test('kein part of außer in generierten Dateien', () {
    for (final file in _dartFiles('lib')) {
      if (file.path.endsWith('.g.dart')) continue;
      expect(
        file.readAsStringSync(),
        isNot(matches(RegExp('^part of ', multiLine: true))),
        reason: file.path,
      );
    }
  });

  test('Gsd-Konvention: exportierte Typen beginnen mit Gsd, exportierte '
      'Dateien mit gsd_', () {
    for (final export in _barrelExports()) {
      final fileName = export.split('/').last;
      final source = File(_exportedFilePath(export)).readAsStringSync();
      final types = _typeDeclaration
          .allMatches(source)
          .map((match) => match.group(1)!)
          .where((name) => !name.startsWith('_'));

      expect(fileName, startsWith('gsd_'), reason: export);
      for (final type in types) {
        expect(type, startsWith('Gsd'), reason: '$export: $type');
      }
    }
  });

  test('nirgends GSD in Großbuchstaben als Typpräfix', () {
    for (final file in _dartFiles('lib')) {
      expect(
        file.readAsStringSync(),
        isNot(matches(RegExp(r'\bGSD[A-Z]'))),
        reason: file.path,
      );
    }
  });

  test('neuer Einstieg exportiert Runtime-Steuerung', () {
    expect(GsdRequestPriority.values, contains(GsdRequestPriority.low));
    expect(_compileExecutionScopeCalls, isA<Function>());
  });

  test('native V1/V3-Endpunkte importieren kein raw', () {
    final endpointFiles = <String>[
      'lib/src/v1',
      'lib/src/v3',
    ].expand(_dartFiles);

    expect(endpointFiles, isNotEmpty);
    for (final file in endpointFiles) {
      final source = file.readAsStringSync();
      final imports = source
          .split('\n')
          .where((line) => line.trimLeft().startsWith('import '));

      final importSource = imports.join('\n');
      expect(importSource, isNot(contains('/raw/')), reason: file.path);

      final implementationSource = source
          .replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '')
          .replaceAll(RegExp('//.*'), '');
      expect(
        implementationSource,
        isNot(contains('customRequest(')),
        reason: file.path,
      );
      expect(
        implementationSource,
        isNot(contains('GsdRawApi(')),
        reason: file.path,
      );
    }
  });

  test('native V1/V3-Endpunkte legen keine Ausfuehrungspolicy offen', () {
    final endpointFiles = <String>[
      'lib/src/v1',
      'lib/src/v3',
    ].expand(_dartFiles);

    expect(endpointFiles, isNotEmpty);
    for (final file in endpointFiles) {
      final implementationSource = file
          .readAsStringSync()
          .replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '')
          .replaceAll(RegExp('//.*'), '');

      // Priorität und Buffering sind ausschließlich Zone-gesteuerte
      // Runtime-Policy - kein öffentlicher Endpoint darf sie als Parameter
      // oder Typ hereinreichen.
      for (final policyToken in <String>[
        'GsdRequestPriority',
        'BufferingPolicy',
        'RuntimeExecutionPolicy',
        'skipBuffering',
      ]) {
        expect(
          implementationSource,
          isNot(contains(policyToken)),
          reason: '${file.path}: $policyToken',
        );
      }
    }
  });
}
