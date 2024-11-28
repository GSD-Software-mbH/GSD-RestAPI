import 'dart:convert';
import 'dart:typed_data';
// ignore: avoid_web_libraries_in_flutter
import 'dart:js_util' as js_util;
import 'package:encryption/extension.dart';
import 'package:encryption/web/webgeneratekeyoptions.dart';
import 'package:encryption/web/webhashalgorithm.dart';
import 'package:js/js.dart';
import 'package:pointycastle/export.dart';

// Zugriff auf `window.crypto.subtle` in JavaScript
@JS('window.crypto.subtle')
external dynamic get subtle;

class WebRSAKeyGenerator {
  // Schlüssel generieren
  static Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>> generateRSAKeys({int bitLength = 2048}) async {   
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

    final rsaPublicKeyPEM = await _exportPublicKey(publicKey);
    final rsaPrivateKeyPEM = await _exportPrivateKey(privateKey);

    RSAPublicKey rsaPublicKey = rsaPublicKeyPEM.parsePublicKeyFromPem();
    RSAPrivateKey rsaPrivateKey = rsaPrivateKeyPEM.parsePrivateKeyFromPem();

    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
          rsaPublicKey, rsaPrivateKey);
  }

  static Future<String> _exportPublicKey(dynamic publicKey) async {
    // Exportiere den Schlüssel im SPKI-Format
    final spkiKey = await js_util.promiseToFuture(
      js_util.callMethod(subtle, 'exportKey', ['spki', publicKey])
    );

    final spkiKeyBuffer = spkiKey as ByteBuffer; // Typcasting in ByteBuffer
    final spkiKeyBytes = Uint8List.view(spkiKeyBuffer); // Konvertierung in Uint8List
    final base64Key = base64Encode(spkiKeyBytes); // Base64-Kodierung

    // Füge die PEM-Header und -Footer hinzu
    final pemKey = [
      '-----BEGIN PUBLIC KEY-----',
      ...RegExp('.{1,64}').allMatches(base64Key).map((m) => m.group(0)!), // Zeilenumbrüche
      '-----END PUBLIC KEY-----'
    ].join('\n');

    return pemKey;
  }

  static Future<String> _exportPrivateKey(dynamic privateKey) async {
    // Exportiere den Schlüssel im PKCS8-Format
    final pkcs8Key = await js_util.promiseToFuture(
      js_util.callMethod(subtle, 'exportKey', ['pkcs8', privateKey])
    );

    final pkcs8KeyBuffer = pkcs8Key as ByteBuffer; // Typcasting in ByteBuffer
    final pkcs8KeyBytes = Uint8List.view(pkcs8KeyBuffer); // Konvertierung in Uint8List
    final base64Key = base64Encode(pkcs8KeyBytes); // Base64-Kodierung

    // Füge die PEM-Header und -Footer hinzu
    final pemKey = [
      '-----BEGIN PRIVATE KEY-----',
      ...RegExp('.{1,64}').allMatches(base64Key).map((m) => m.group(0)!), // Zeilenumbrüche
      '-----END PRIVATE KEY-----'
    ].join('\n');

    return pemKey;
  }
}