import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

Future<void> _compileExecutionScopeCalls(DOCUframeApi api) async {
  await api.executeWithoutBuffering(() async => 1);
  await api.executeWithPriority(() async => 1, RequestPriority.low);
}

void main() {
  test('neuer Einstieg exportiert keine internen src-Libraries', () {
    final String source = File('lib/docuframe_api.dart').readAsStringSync();
    final Iterable<String> exports = source
        .split('\n')
        .where((line) => line.trimLeft().startsWith('export '));

    expect(exports.join('\n'), isNot(contains('/src/')));
  });

  test('Legacy-Oberflaeche bleibt am Legacy-Einstieg', () {
    final String source = File('lib/docuframe_api.dart').readAsStringSync();

    for (final String hiddenType in <String>[
      'RestApiDOCUframeManager',
      'RestApiRequest',
      'RestAPIBufferedRequest',
    ]) {
      expect(source, contains(hiddenType), reason: hiddenType);
    }
  });

  test('neuer Einstieg exportiert Runtime-Steuerung', () {
    expect(RequestPriority.values, contains(RequestPriority.low));
    expect(_compileExecutionScopeCalls, isA<Function>());
  });

  test('native V1/V2-Endpunkte importieren weder legacy noch raw', () {
    final Iterable<File> endpointFiles = <String>['lib/v1', 'lib/v2']
        .expand(
          (directory) =>
              Directory(directory).listSync(recursive: true).whereType<File>(),
        )
        .where((file) => file.path.endsWith('.dart'));

    expect(endpointFiles, isNotEmpty);
    for (final File file in endpointFiles) {
      final String source = file.readAsStringSync();
      final Iterable<String> imports = source
          .split('\n')
          .where((line) => line.trimLeft().startsWith('import '));

      final String importSource = imports.join('\n');
      expect(importSource, isNot(contains('/legacy/')), reason: file.path);
      expect(importSource, isNot(contains('/raw/')), reason: file.path);

      final String implementationSource = source
          .replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '')
          .replaceAll(RegExp(r'//.*'), '');
      expect(
        implementationSource,
        isNot(contains('RestApiDOCUframeManager')),
        reason: file.path,
      );
      expect(
        implementationSource,
        isNot(contains('customRequest(')),
        reason: file.path,
      );
      expect(
        implementationSource,
        isNot(contains('RawApi(')),
        reason: file.path,
      );
    }
  });

  test('native V1/V2-Endpunkte legen keine Ausfuehrungspolicy offen', () {
    final Iterable<File> endpointFiles = <String>['lib/v1', 'lib/v2']
        .expand(
          (directory) =>
              Directory(directory).listSync(recursive: true).whereType<File>(),
        )
        .where((file) => file.path.endsWith('.dart'));

    expect(endpointFiles, isNotEmpty);
    for (final File file in endpointFiles) {
      final String implementationSource = file
          .readAsStringSync()
          .replaceAll(RegExp(r'/\*[\s\S]*?\*/'), '')
          .replaceAll(RegExp(r'//.*'), '');

      // Priorität und Buffering sind ausschließlich Zone-gesteuerte
      // Runtime-Policy - kein öffentlicher Endpoint darf sie als Parameter
      // oder Typ hereinreichen.
      for (final String policyToken in <String>[
        'RequestPriority',
        'ApiRequestPriority',
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
