import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

void main() {
  group('GsdUploadFile', () {
    test('should create file with path only', () {
      final file = GsdUploadFile(
        name: 'test.txt',
        path: '/path/to/test.txt',
      );

      expect(file.name, equals('test.txt'));
      expect(file.path, equals('/path/to/test.txt'));
      expect(file.bytes, isNull);
      expect(file.isPath, isTrue);
      expect(file.isBytes, isFalse);
    }, testOn: 'vm');

    test('should create file with bytes only', () {
      final bytes = Uint8List.fromList([1, 2, 3, 4, 5]);
      final file = GsdUploadFile(name: 'test.txt', bytes: bytes);

      expect(file.name, equals('test.txt'));
      expect(file.path, isNull);
      expect(file.bytes, equals(bytes));
      expect(file.isPath, isFalse);
      expect(file.isBytes, isTrue);
    });

    test(
      'should throw assertion error when both path and bytes are provided',
      () {
        expect(
          () => GsdUploadFile(
            name: 'test.txt',
            path: '/path/to/test.txt',
            bytes: Uint8List.fromList([1, 2, 3]),
          ),
          throwsA(isA<AssertionError>()),
        );
      },
      testOn: 'vm',
    );

    test(
      'should throw assertion error when neither path nor bytes are provided',
      () {
        expect(
          () => GsdUploadFile(name: 'test.txt'),
          throwsA(isA<AssertionError>()),
        );
      },
    );

    test('should create file from path using fromPath constructor', () {
      final file = GsdUploadFile.fromPath(path: '/path/to/document.pdf');

      expect(file.name, equals('document.pdf'));
      expect(file.path, equals('/path/to/document.pdf'));
      expect(file.bytes, isNull);
      expect(file.isPath, isTrue);
      expect(file.isBytes, isFalse);
    }, testOn: 'vm');

    test('should create file from bytes using fromBytes constructor', () {
      final bytes = Uint8List.fromList([72, 101, 108, 108, 111]);
      final file = GsdUploadFile.fromBytes(name: 'hello.txt', bytes: bytes);

      expect(file.name, equals('hello.txt'));
      expect(file.path, isNull);
      expect(file.bytes, equals(bytes));
      expect(file.isPath, isFalse);
      expect(file.isBytes, isTrue);
    });

    test('should extract filename from complex path', () {
      final file = GsdUploadFile.fromPath(
        path: '/very/deep/nested/path/to/image.jpg',
      );

      expect(file.name, equals('image.jpg'));
    }, testOn: 'vm');

    test('should handle Windows-style path separators', () {
      final file = GsdUploadFile.fromPath(
        path: r'C:\Users\Documents\file.docx',
      );

      expect(file.name, equals('file.docx'));
    }, testOn: 'vm');

    test('should handle empty bytes array', () {
      final file = GsdUploadFile.fromBytes(
        name: 'empty.txt',
        bytes: Uint8List.fromList([]),
      );

      expect(file.bytes, isEmpty);
      expect(file.isBytes, isTrue);
    });

    test('should handle rename', () {
      final file = GsdUploadFile.fromBytes(
        name: 'empty.txt',
        bytes: Uint8List.fromList([]),
      );

      const newName = 'renamed.txt';

      file.name = newName;

      expect(file.name, newName);
    });

    group('im Browser', () {
      test('fromPath wirft UnsupportedError', () {
        expect(
          () => GsdUploadFile.fromPath(path: '/path/to/document.pdf'),
          throwsUnsupportedError,
        );
      });

      test('ein Pfad im Standardkonstruktor wirft UnsupportedError', () {
        expect(
          () => GsdUploadFile(name: 'test.txt', path: '/path/to/test.txt'),
          throwsUnsupportedError,
        );
      });
    }, testOn: 'browser');
  });
}
