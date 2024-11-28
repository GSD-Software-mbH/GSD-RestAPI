import 'dart:convert';
import 'dart:typed_data';
// ignore: avoid_web_libraries_in_flutter
import 'dart:js_util' as js_util;
import 'package:encryption/web/webasymmetrickeypair.dart';
import 'package:encryption/web/webgeneratekeyoptions.dart';
import 'package:encryption/web/webhashalgorithm.dart';
import 'package:flutter/foundation.dart';
import 'package:js/js.dart';

// Zugriff auf `window.crypto.subtle` in JavaScript
@JS('window.crypto.subtle')
external dynamic get subtle;

class WebRSAEncryptionManager {
  // Schlüssel generieren
  static Future<WebAsymmetricKeyPair> generateRSAKeys(
      {int bitLength = 2048}) async {
    final options = GenerateKeyOptions(
      name: 'RSA-OAEP',
      modulusLength: bitLength,
      publicExponent: Uint8List.fromList([0x01, 0x00, 0x01]),
      hash: HashAlgorithm(name: 'SHA-256'),
    );

    dynamic keypair = await js_util.promiseToFuture(
      js_util.callMethod(subtle, 'generateKey', [
        options,
        true,
        ['encrypt', 'decrypt']
      ]),
    );

    final publicKey = js_util.getProperty(keypair, 'publicKey');
    final privateKey = js_util.getProperty(keypair, 'privateKey');

    return WebAsymmetricKeyPair(publicKey, privateKey);
  }

  // Daten verschlüsseln
  static Future<Uint8List> encryptData(dynamic publicKey, String data) async {
    final algorithm = {'name': 'RSA-OAEP'};

    // Debugging
    debugPrint('Algorithm: ${jsonEncode(algorithm)}');
    debugPrint('Key Algorithm: ${js_util.getProperty(publicKey, "algorithm")}');
    debugPrint('Key Type: ${js_util.getProperty(publicKey, "type")}');
    debugPrint('Key Usages: ${js_util.getProperty(publicKey, "usages")}');

    final encryptedData = await js_util.promiseToFuture(
      js_util.callMethod(subtle, 'encrypt', [
        algorithm, // Algorithmus
        publicKey, // Schlüssel
        Uint8List.fromList(utf8.encode(data)), // Daten
      ]),
    );
    return Uint8List.view((encryptedData as ByteBuffer));
  }

  // Daten entschlüsseln
  static Future<String> decryptData(
      dynamic privateKey, Uint8List encryptedData) async {
    final algorithm = {'name': 'RSA-OAEP'};
    debugPrint('Private Key: $privateKey');
    final decryptedData = await js_util.promiseToFuture(
      js_util.callMethod(subtle, 'decrypt', [
        algorithm,
        privateKey,
        encryptedData,
      ]),
    );
    return utf8.decode(Uint8List.view((decryptedData as ByteBuffer)));
  }
}
