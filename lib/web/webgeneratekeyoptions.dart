import 'package:encryption/web/webhashalgorithm.dart';
import 'package:js/js.dart';
import 'dart:typed_data';

// Optionen für die Schlüsselerzeugung
@JS()
@anonymous
class GenerateKeyOptions {
  external factory GenerateKeyOptions({
    String name,
    int modulusLength,
    Uint8List publicExponent,
    HashAlgorithm hash,
  });
}