import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

void main() {
  group('GsdFileDownload', () {
    test('ist gleich bei gleichen Bytes und Headern', () {
      expect(
        GsdFileDownload(
          bytes: Uint8List.fromList([1, 2]),
          headers: const {'content-type': 'image/png'},
        ),
        GsdFileDownload(
          bytes: Uint8List.fromList([1, 2]),
          headers: const {'content-type': 'image/png'},
        ),
      );
    });

    test('hat ohne Angabe keine Header', () {
      expect(GsdFileDownload(bytes: Uint8List(0)).headers, isEmpty);
    });
  });
}
