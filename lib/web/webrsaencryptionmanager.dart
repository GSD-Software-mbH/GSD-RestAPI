import 'dart:convert';
import 'dart:typed_data';
// ignore: avoid_web_libraries_in_flutter
import 'dart:js_util' as js_util;
import 'package:encryption/extension.dart';
import 'package:encryption/web/webgeneratekeyoptions.dart';
import 'package:encryption/web/webhashalgorithm.dart';
import 'package:js/js.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/pointycastle.dart';

// Zugriff auf `window.crypto.subtle` in JavaScript
@JS('window.crypto.subtle')
external dynamic get subtle;

class WebRSAEncryptionManager {
  // Schlüssel generieren
  static Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>> generateRSAKeys(
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

    final rsaPublicKeyPEM = await _exportPublicKey(publicKey);
    final rsaPrivateKeyPEM = await _exportPrivateKey(privateKey);

    RSAPublicKey rsaPublicKey = rsaPublicKeyPEM.parsePublicKeyFromPem();
    RSAPrivateKey rsaPrivateKey = rsaPrivateKeyPEM.parsePrivateKeyFromPem();

    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
        rsaPublicKey, rsaPrivateKey);
  }

  // Daten verschlüsseln
  static Future<Uint8List> encryptData(
      RSAPublicKey publicKey, String data) async {
    // Public Key in SPKI-Format konvertieren
    final spkiKey = _encodePublicKeyToSPKI(publicKey);

    // SPKI-Schlüssel in WebCrypto importieren
    final cryptoKey = await js_util.promiseToFuture(
      js_util.callMethod(subtle, 'importKey', [
        'spki',
        spkiKey.buffer,
        {
          'name': 'RSA-OAEP',
          'hash': {'name': 'SHA-256'}
        },
        false,
        ['encrypt']
      ]),
    );

    final encryptedData = await js_util.promiseToFuture(
      js_util.callMethod(subtle, 'encrypt', [
        {'name': 'RSA-OAEP'},
        cryptoKey,
        Uint8List.fromList(utf8.encode(data)),
      ]),
    );
    return Uint8List.fromList(encryptedData as List<int>);
  }

  // Daten entschlüsseln
  static Future<String> decryptData(
      RSAPrivateKey privateKey, Uint8List encryptedData) async {
    // Private Key in PKCS#8-Format konvertieren
    final pkcs8Key = _encodePrivateKeyToPKCS8(privateKey);

    // PKCS#8-Schlüssel in WebCrypto importieren
    final cryptoKey = await js_util.promiseToFuture(
      js_util.callMethod(subtle, 'importKey', [
        'pkcs8',
        pkcs8Key.buffer,
        {
          'name': 'RSA-OAEP',
          'hash': {'name': 'SHA-256'}
        },
        false,
        ['decrypt']
      ]),
    );

    final decryptedData = await js_util.promiseToFuture(
      js_util.callMethod(subtle, 'decrypt', [
        {'name': 'RSA-OAEP'},
        cryptoKey,
        encryptedData,
      ]),
    );
    return utf8.decode(Uint8List.fromList(decryptedData as List<int>));
  }

  static Future<String> _exportPublicKey(dynamic publicKey) async {
    // Exportiere den Schlüssel im SPKI-Format
    final spkiKey = await js_util.promiseToFuture(
        js_util.callMethod(subtle, 'exportKey', ['spki', publicKey]));

    final spkiKeyBuffer = spkiKey as ByteBuffer; // Typcasting in ByteBuffer
    final spkiKeyBytes =
        Uint8List.view(spkiKeyBuffer); // Konvertierung in Uint8List
    final base64Key = base64Encode(spkiKeyBytes); // Base64-Kodierung

    // Füge die PEM-Header und -Footer hinzu
    final pemKey = [
      '-----BEGIN PUBLIC KEY-----',
      ...RegExp('.{1,64}')
          .allMatches(base64Key)
          .map((m) => m.group(0)!), // Zeilenumbrüche
      '-----END PUBLIC KEY-----'
    ].join('\n');

    return pemKey;
  }

  static Future<String> _exportPrivateKey(dynamic privateKey) async {
    // Exportiere den Schlüssel im PKCS8-Format
    final pkcs8Key = await js_util.promiseToFuture(
        js_util.callMethod(subtle, 'exportKey', ['pkcs8', privateKey]));

    final pkcs8KeyBuffer = pkcs8Key as ByteBuffer; // Typcasting in ByteBuffer
    final pkcs8KeyBytes =
        Uint8List.view(pkcs8KeyBuffer); // Konvertierung in Uint8List
    final base64Key = base64Encode(pkcs8KeyBytes); // Base64-Kodierung

    // Füge die PEM-Header und -Footer hinzu
    final pemKey = [
      '-----BEGIN PRIVATE KEY-----',
      ...RegExp('.{1,64}')
          .allMatches(base64Key)
          .map((m) => m.group(0)!), // Zeilenumbrüche
      '-----END PRIVATE KEY-----'
    ].join('\n');

    return pemKey;
  }

  static Uint8List _encodePublicKeyToSPKI(RSAPublicKey publicKey) {
    final modulusBytes = publicKey.modulus!;
    final exponentBytes = publicKey.publicExponent!;

    // ASN.1 Struktur für SPKI
    final spki = ASN1Sequence();
    final algorithm = ASN1Sequence();
    algorithm.add(ASN1ObjectIdentifier.fromName('rsaEncryption'));
    algorithm.add(ASN1Null());
    spki.add(algorithm);

    final subjectPublicKey = ASN1BitString();
    final subjectSequence = ASN1Sequence();
    subjectSequence.add(ASN1Integer(modulusBytes));
    subjectSequence.add(ASN1Integer(exponentBytes));
    subjectPublicKey.valueBytes = subjectSequence.encodedBytes;
    spki.add(subjectPublicKey);

    return spki.encodedBytes!;
  }

  static Uint8List _encodePrivateKeyToPKCS8(RSAPrivateKey privateKey) {
    final modulusBytes = privateKey.modulus!;
    final publicExponentBytes = privateKey.publicExponent!;
    final privateExponentBytes = privateKey.privateExponent!;
    final prime1Bytes = privateKey.p!;
    final prime2Bytes = privateKey.q!;
    final exponent1Bytes = 
        privateKey.privateExponent! % (privateKey.p! - BigInt.one);
    final exponent2Bytes = 
        privateKey.privateExponent! % (privateKey.q! - BigInt.one);
    final coefficientBytes =
        privateKey.q!.modInverse(privateKey.p!);

    // ASN.1 Struktur für PKCS#8
    final pkcs8 = ASN1Sequence();
    final version = ASN1Integer(BigInt.from(0));
    final privateKeyAlgorithm = ASN1Sequence();
    privateKeyAlgorithm.add(ASN1ObjectIdentifier.fromName('rsaEncryption'));
    privateKeyAlgorithm.add(ASN1Null());
    final privateKeySequence = ASN1Sequence();
    privateKeySequence.add(ASN1Integer(BigInt.from(0))); // Version
    privateKeySequence.add(ASN1Integer(modulusBytes));
    privateKeySequence.add(ASN1Integer(publicExponentBytes));
    privateKeySequence.add(ASN1Integer(privateExponentBytes));
    privateKeySequence.add(ASN1Integer(prime1Bytes));
    privateKeySequence.add(ASN1Integer(prime2Bytes));
    privateKeySequence.add(ASN1Integer(exponent1Bytes));
    privateKeySequence.add(ASN1Integer(exponent2Bytes));
    privateKeySequence.add(ASN1Integer(coefficientBytes));
    final privateKeyOctetString =
        ASN1OctetString(octets: privateKeySequence.encodedBytes);

    pkcs8.add(version);
    pkcs8.add(privateKeyAlgorithm);
    pkcs8.add(privateKeyOctetString);

    return pkcs8.encodedBytes!;
  }
}
