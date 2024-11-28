import 'dart:typed_data';
// ignore: avoid_web_libraries_in_flutter
import 'dart:js_util' as js_util;
import 'package:encryption/web/webgeneratekeyoptions.dart';
import 'package:encryption/web/webhashalgorithm.dart';
import 'package:js/js.dart';

// Zugriff auf `window.crypto.subtle` in JavaScript
@JS('window.crypto.subtle')
external dynamic get subtle;

class WebRSAKeyGenerator {
  // Schlüssel generieren
  static Future<dynamic> generateRSAKeys() async {
    final options = GenerateKeyOptions(
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: Uint8List.fromList([0x01, 0x00, 0x01]),
      hash: HashAlgorithm(name: 'SHA-256'),
    );
    return js_util.promiseToFuture(
      js_util.callMethod(subtle, 'generateKey', [
        options,
        true,
        ['encrypt', 'decrypt']
      ]),
    );
  }
}