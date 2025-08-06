import 'package:gsd_encryption/web/webhashalgorithm.dart';
import 'dart:js_interop';

/// Extension Type für RSA-Schlüsselgenerierungsoptionen der Web Crypto API.
/// 
/// Diese Klasse stellt eine typisierte Schnittstelle zu den Optionen dar, die
/// für die Generierung von RSA-Schlüsseln mit der Web Crypto API benötigt werden.
/// Sie kapselt die JavaScript-Objektstruktur, die von der generateKey-Methode
/// der SubtleCrypto-Schnittstelle erwartet wird.
/// 
/// **Verwendung:**
/// Diese Klasse wird intern vom WebRSAEncryptionManager verwendet und stellt
/// sicher, dass die Parameter für die Schlüsselgenerierung korrekt an die
/// Web Crypto API übergeben werden.
/// 
/// **Parameter:**
/// - **name**: Der Algorithmusname (z.B. "RSA-OAEP")
/// - **modulusLength**: Die Bit-Länge des RSA-Modulus
/// - **publicExponent**: Der öffentliche Exponent als Byte-Array
/// - **hash**: Der Hash-Algorithmus für OAEP-Padding
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