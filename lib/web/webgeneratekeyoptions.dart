import 'package:gsd_encryption/web/webhashalgorithm.dart';
import 'dart:js_interop';

// Optionen für die Schlüsselerzeugung
@JS()
@anonymous
extension type GenerateKeyOptions._(JSObject _) implements JSObject {
  external factory GenerateKeyOptions({
    String name,
    int modulusLength,
    JSUint8Array publicExponent,
    HashAlgorithm hash,
  });
}