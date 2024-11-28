import 'dart:typed_data';
import 'package:encryption/web/webasymmetrickeypair.dart';

class WebRSAEncryptionManager {
  // Schlüssel generieren
  static Future<WebAsymmetricKeyPair> generateRSAKeys({int bitLength = 2048}) async {   
    return WebAsymmetricKeyPair(null, null);
  }

  // Daten verschlüsseln
  static Future<Uint8List> encryptData(dynamic publicKey, String data) async {
    return Uint8List.fromList([]);
  }

  // Daten entschlüsseln
  static Future<String> decryptData(dynamic privateKey, Uint8List encryptedData) async {
    return "";
  }
}