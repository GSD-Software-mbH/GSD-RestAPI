import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

void main() {
  group('RestApiUploadFile', () {
    test('should create file with path only', () {
      final file = RestApiUploadFile(
        name: 'test.txt',
        path: '/path/to/test.txt',
      );

      expect(file.name, equals('test.txt'));
      expect(file.path, equals('/path/to/test.txt'));
      expect(file.bytes, isNull);
      expect(file.isPath, isTrue);
      expect(file.isBytes, isFalse);
    });

    test('should create file with bytes only', () {
      final bytes = Uint8List.fromList([1, 2, 3, 4, 5]);
      final file = RestApiUploadFile(name: 'test.txt', bytes: bytes);

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
          () => RestApiUploadFile(
            name: 'test.txt',
            path: '/path/to/test.txt',
            bytes: Uint8List.fromList([1, 2, 3]),
          ),
          throwsAssertionError,
        );
      },
    );

    test(
      'should throw assertion error when neither path nor bytes are provided',
      () {
        expect(() => RestApiUploadFile(name: 'test.txt'), throwsAssertionError);
      },
    );

    test('should create file from path using fromPath constructor', () {
      final file = RestApiUploadFile.fromPath(path: '/path/to/document.pdf');

      expect(file.name, equals('document.pdf'));
      expect(file.path, equals('/path/to/document.pdf'));
      expect(file.bytes, isNull);
      expect(file.isPath, isTrue);
      expect(file.isBytes, isFalse);
    });

    test('should create file from bytes using fromBytes constructor', () {
      final bytes = Uint8List.fromList([72, 101, 108, 108, 111]);
      final file = RestApiUploadFile.fromBytes(name: 'hello.txt', bytes: bytes);

      expect(file.name, equals('hello.txt'));
      expect(file.path, isNull);
      expect(file.bytes, equals(bytes));
      expect(file.isPath, isFalse);
      expect(file.isBytes, isTrue);
    });

    test('should extract filename from complex path', () {
      final file = RestApiUploadFile.fromPath(
        path: '/very/deep/nested/path/to/image.jpg',
      );

      expect(file.name, equals('image.jpg'));
    });

    test('should handle Windows-style path separators', () {
      final file = RestApiUploadFile.fromPath(
        path: 'C:\\Users\\Documents\\file.docx',
      );

      expect(file.name, equals('file.docx'));
    });

    test('should handle empty bytes array', () {
      final file = RestApiUploadFile.fromBytes(
        name: 'empty.txt',
        bytes: Uint8List.fromList([]),
      );

      expect(file.bytes, isEmpty);
      expect(file.isBytes, isTrue);
    });

    test('should handle rename', () {
      final file = RestApiUploadFile.fromBytes(
        name: 'empty.txt',
        bytes: Uint8List.fromList([]),
      );

      String newName = 'renamed.txt';

      file.name = newName;

      expect(file.name, newName);
    });
  });
}
