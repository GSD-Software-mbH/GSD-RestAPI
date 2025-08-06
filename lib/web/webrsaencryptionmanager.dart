import 'dart:convert';
import 'dart:typed_data';
import 'dart:js_interop';
import 'package:gsd_encryption/gsd_encryption.dart';
import 'package:gsd_encryption/web/webgeneratekeyoptions.dart';
import 'package:gsd_encryption/web/webhashalgorithm.dart';
import 'package:web/web.dart';
import 'package:pointycastle/export.dart';

// Zugriff auf `window.crypto.subtle` ist bereits über window.crypto.subtle verfügbar

/// Extension Type für CryptoKeyPair der Web Crypto API.
/// 
/// Dieses Extension Type stellt eine typisierte Schnittstelle zu den CryptoKeyPair-Objekten
/// der Browser Web Crypto API dar. Es ermöglicht den Zugriff auf die öffentlichen und
/// privaten Schlüssel, die von der generateKey-Methode zurückgegeben werden.
@JS()
@anonymous
extension type CryptoKeyPair._(JSObject _) implements JSObject {
  external CryptoKey get publicKey;
  external CryptoKey get privateKey;
}

/// Web-spezifischer RSA-Verschlüsselungsmanager für Browser-Umgebungen.
/// 
/// Diese Klasse bietet RSA-Verschlüsselungsfunktionalität speziell für Web-Plattformen
/// und nutzt die native Web Crypto API des Browsers für optimale Performance und Sicherheit.
/// Sie ist als Alternative zur pointycastle-Bibliothek auf Web-Plattformen konzipiert.
/// 
/// **Hauptfunktionen:**
/// - RSA-Schlüsselgenerierung mit Web Crypto API
/// - OAEP-Padding mit SHA-256 Hash-Algorithmus
/// - Export von Schlüsseln im PEM-Format
/// - Kompatibilität mit der gsd_encryption-Bibliothek
/// 
/// **Technische Details:**
/// - Verwendet RSA-OAEP für sichere Verschlüsselung
/// - Unterstützt variable Schlüssellängen (Standard: 2048 Bit)
/// - Exportiert Schlüssel in SPKI (public) und PKCS#8 (private) Formaten
/// - Automatische Konvertierung in pointycastle-kompatible Objekte
/// 
/// **Verwendung:**
/// Diese Klasse wird automatisch vom EncryptionManager verwendet, wenn die
/// Anwendung in einer Web-Umgebung läuft. Direkte Verwendung ist normalerweise
/// nicht erforderlich.
class WebRSAEncryptionManager {
  /// Generiert ein RSA-Schlüsselpaar mit der Web Crypto API.
  /// 
  /// Diese statische Methode nutzt die native Web Crypto API des Browsers zur
  /// Generierung eines kryptographisch sicheren RSA-Schlüsselpaars. Die generierten
  /// Schlüssel werden automatisch in das PEM-Format exportiert und dann in
  /// pointycastle-kompatible Objekte konvertiert.
  /// 
  /// Parameter:
  /// - [bitLength]: Die Bit-Länge des zu generierenden Schlüssels (Standard: 2048)
  /// 
  /// Rückgabe: AsymmetricKeyPair mit RSA-öffentlichem und -privatem Schlüssel
  /// 
  /// **Technische Details:**
  /// - Verwendet RSA-OAEP-Algorithmus für sichere Schlüsselgenerierung
  /// - Hash-Algorithmus: SHA-256 für optimale Sicherheit
  /// - Öffentlicher Exponent: 65537 (0x010001) als Standard
  /// - Schlüssel sind für 'encrypt' und 'decrypt' Operationen konfiguriert
  /// 
  /// **Performance:**
  /// Die Web Crypto API nutzt Hardware-Beschleunigung wenn verfügbar,
  /// was zu deutlich besserer Performance führt als Software-basierte Implementierungen.
  /// 
  /// Wirft eine Exception, wenn die Web Crypto API nicht verfügbar ist oder
  /// die Schlüsselgenerierung fehlschlägt.
  static Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>> generateRSAKeys({int bitLength = 2048}) async {   
    final publicExponentArray = Uint8List.fromList([0x01, 0x00, 0x01]);
    
    final options = GenerateKeyOptions(
      name: 'RSA-OAEP',
      modulusLength: bitLength,
      publicExponent: publicExponentArray.toJS,
      hash: HashAlgorithm(name: 'SHA-256'),
    );

    final usages = ['encrypt', 'decrypt'].map((s) => s.toJS).toList().toJS;

    final keypairResult = await window.crypto.subtle.generateKey(
      options,
      true,
      usages,
    ).toDart;

    final keypair = keypairResult as CryptoKeyPair;
    final publicKey = keypair.publicKey;
    final privateKey = keypair.privateKey;

    final rsaPublicKeyPEM = await _exportPublicKey(publicKey);
    final rsaPrivateKeyPEM = await _exportPrivateKey(privateKey);

    RSAPublicKey rsaPublicKey = rsaPublicKeyPEM.parsePublicKeyFromPem();
    RSAPrivateKey rsaPrivateKey = rsaPrivateKeyPEM.parsePrivateKeyFromPem();

    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
          rsaPublicKey, rsaPrivateKey);
  }

  /// Exportiert einen CryptoKey als PEM-formatierten öffentlichen Schlüssel.
  /// 
  /// Diese private statische Methode konvertiert einen Web Crypto API CryptoKey
  /// in das standardisierte PEM-Format für öffentliche Schlüssel. Das resultierende
  /// Format ist kompatibel mit OpenSSL und anderen kryptographischen Bibliotheken.
  /// 
  /// Parameter:
  /// - [publicKey]: Der zu exportierende öffentliche CryptoKey
  /// 
  /// Rückgabe: PEM-formatierter String mit "-----BEGIN PUBLIC KEY-----" Headern
  /// 
  /// **Verarbeitungsschritte:**
  /// 1. Export des Schlüssels im SPKI-Format (Subject Public Key Info)
  /// 2. Konvertierung des ArrayBuffers in Uint8List
  /// 3. Base64-Kodierung der binären Daten
  /// 4. Formatierung mit PEM-Headern und 64-Zeichen-Zeilenlänge
  /// 
  /// Das SPKI-Format ist der Standard für öffentliche Schlüssel und wird
  /// von den meisten kryptographischen Bibliotheken unterstützt.
  static Future<String> _exportPublicKey(CryptoKey publicKey) async {
    // Exportiere den Schlüssel im SPKI-Format
    final spkiKey = await window.crypto.subtle.exportKey('spki', publicKey).toDart;

    final spkiKeyBuffer = (spkiKey as JSArrayBuffer).toDart; // Verwende toDart für die Konvertierung
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

  /// Exportiert einen CryptoKey als PEM-formatierten privaten Schlüssel.
  /// 
  /// Diese private statische Methode konvertiert einen Web Crypto API CryptoKey
  /// in das standardisierte PEM-Format für private Schlüssel. Das resultierende
  /// Format folgt dem PKCS#8-Standard und ist kompatibel mit OpenSSL und
  /// anderen kryptographischen Bibliotheken.
  /// 
  /// Parameter:
  /// - [privateKey]: Der zu exportierende private CryptoKey
  /// 
  /// Rückgabe: PEM-formatierter String mit "-----BEGIN PRIVATE KEY-----" Headern
  /// 
  /// **Verarbeitungsschritte:**
  /// 1. Export des Schlüssels im PKCS#8-Format
  /// 2. Konvertierung des ArrayBuffers in Uint8List
  /// 3. Base64-Kodierung der binären Daten
  /// 4. Formatierung mit PEM-Headern und 64-Zeichen-Zeilenlänge
  /// 
  /// **Sicherheitshinweis:**
  /// Private Schlüssel sollten sicher gespeichert und übertragen werden.
  /// Das PKCS#8-Format unterstützt optional Passwort-basierte Verschlüsselung,
  /// diese Implementierung exportiert jedoch unverschlüsselte Schlüssel.
  static Future<String> _exportPrivateKey(CryptoKey privateKey) async {
    // Exportiere den Schlüssel im PKCS8-Format
    final pkcs8Key = await window.crypto.subtle.exportKey('pkcs8', privateKey).toDart;

    final pkcs8KeyBuffer = (pkcs8Key as JSArrayBuffer).toDart; // Verwende toDart für die Konvertierung
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