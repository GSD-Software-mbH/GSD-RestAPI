import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

/// Erweiterung für `String`, um die Parsing-Funktionalität für RSA-öffentliche Schlüssel im PEM-Format hinzuzufügen
extension StringExtensions on String {
  /// Funktion zum Parsen eines öffentlichen Schlüssels aus dem PEM-Format und Rückgabe als `RSAPublicKey`
  RSAPublicKey parsePublicKeyFromPem() {
    // Entferne die PEM-Header und -Footer und dekodiere den Base64-PEM-Block
    final pemLines = split('\n');
    final base64String = pemLines
        .where((line) => line.isNotEmpty && !line.startsWith('---'))
        .join();
    final bytes = base64.decode(base64String);

    // Parsen der ASN.1-Struktur
    final asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    // Die oberste Sequenz enthält den Algorithmus-Identifier und den öffentlichen Schlüssel
    final publicKeyBitString = topLevelSeq.elements![1] as ASN1BitString;

    // Extrahiere den Inhalt des BitStrings (dies ist der tatsächliche öffentliche Schlüssel)
    final publicKeyBytes = publicKeyBitString.stringValues;

    // Parsen der Struktur des öffentlichen Schlüssels innerhalb der BitString-Daten
    final publicKeyAsn1Parser = ASN1Parser(Uint8List.fromList(publicKeyBytes!));
    final publicKeySeq = publicKeyAsn1Parser.nextObject() as ASN1Sequence;

    // Extrahiere Modulus (n) und Exponent (e) aus der Sequenz
    final ASN1Integer modulusASN1 = publicKeySeq.elements![0] as ASN1Integer;
    final ASN1Integer exponentASN1 = publicKeySeq.elements![1] as ASN1Integer;

    // Konvertiere Modulus und Exponent in BigInt
    final modulusBigInt =
        BigInt.parse(modulusASN1.valueBytes!.bytesToHex(), radix: 16);
    final exponentBigInt =
        BigInt.parse(exponentASN1.valueBytes!.bytesToHex(), radix: 16);

    // Erstelle den `RSAPublicKey`
    return RSAPublicKey(modulusBigInt, exponentBigInt);
  }

  /// Funktion zum Parsen eines privaten Schlüssels aus dem PEM-Format und Rückgabe als `RSAPrivateKey`
  RSAPrivateKey parsePrivateKeyFromPem() {
    // Entferne die PEM-Header und -Footer und dekodiere den Base64-PEM-Block
    final pemLines = split('\n');
    final base64String = pemLines
        .where((line) => line.isNotEmpty && !line.startsWith('---'))
        .join();
    final bytes = base64.decode(base64String);

    // Parsen der ASN.1-Struktur
    final asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    // PKCS#8-Struktur: Extrahiere den privaten Schlüssel aus dem OctetString
    final privateKeyOctetString = topLevelSeq.elements!.last as ASN1OctetString;
    final privateKeyBytes = privateKeyOctetString.octets;
    final privateKeyParser = ASN1Parser(privateKeyBytes);
    final privateKeySeq = privateKeyParser.nextObject() as ASN1Sequence;

    // Extrahiere die PKCS#1-Schlüsselparameter
    final modulusASN1 = privateKeySeq.elements![1] as ASN1Integer; // n
    final privateExponentASN1 = privateKeySeq.elements![3] as ASN1Integer; // d
    final prime1ASN1 = privateKeySeq.elements![4] as ASN1Integer; // p
    final prime2ASN1 = privateKeySeq.elements![5] as ASN1Integer; // q

    // Konvertiere die Werte in BigInt
    final modulus = _bytesToBigInt(modulusASN1.valueBytes!);
    final privateExponent = _bytesToBigInt(privateExponentASN1.valueBytes!);
    final prime1 = _bytesToBigInt(prime1ASN1.valueBytes!);
    final prime2 = _bytesToBigInt(prime2ASN1.valueBytes!);

    // Erstelle den `RSAPrivateKey`
    return RSAPrivateKey(modulus, privateExponent, prime1, prime2);
  }

  /// Hilfsfunktion: Konvertiert eine Liste von Bytes in BigInt
  BigInt _bytesToBigInt(Uint8List bytes) {
    return BigInt.parse(bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(), radix: 16);
  }
}

/// Erweiterung für `RSAPublicKey`, um die Konvertierung des RSA Public Keys ins PEM-Format hinzuzufügen
extension RSAPublicKeyExtention on RSAPublicKey {
  /// Funktion zur Kodierung des RSA-öffentlichen Schlüssels in das PEM-Format
  String encodeToPem() {
    // Erstelle ASN.1-Objekte für Modulus und Exponent
    final asn1Modulus = ASN1Integer(modulus!);
    final asn1Exponent = ASN1Integer(exponent!);

    // Erstelle die ASN.1-Sequenz, die Modulus und Exponent enthält
    final asn1Seq = ASN1Sequence();
    asn1Seq.add(asn1Modulus);
    asn1Seq.add(asn1Exponent);

    // Kodieren der `publicKey`-Bytes in einen BitString
    final publicKeyBytes = asn1Seq.encode();

    // Verpacke die `publicKeyBytes` in einen BitString
    final publicKeyBitString = ASN1BitString(stringValues: publicKeyBytes);

    // Erstelle die Algorithmen-Sequenz
    final algorithmSeq = ASN1Sequence();
    algorithmSeq.add(ASN1ObjectIdentifier.fromName("rsaEncryption"));
    algorithmSeq.add(ASN1Null());

    // Erstelle die oberste ASN.1-Sequenz, die den Algorithmus und den Schlüssel enthält
    final topLevelSeq = ASN1Sequence();
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeyBitString);

    // Kodierung der Top-Level-Sequenz in Base64
    final base64Key = base64Encode(topLevelSeq.encode());

    // Erstelle das PEM-Format
    final pemString = """
    -----BEGIN PUBLIC KEY-----
    ${_chunked(base64Key, 64)}
    -----END PUBLIC KEY-----
    """;

    return pemString;
  }

  /// Funktion, um den Base64-String in bestimmte Zeilenlängen zu unterteilen
  String _chunked(String str, int chunkSize) {
    final RegExp pattern = RegExp('.{1,$chunkSize}');
    return pattern.allMatches(str).map((m) => m.group(0)).join('\r\n');
  }
}

/// Erweiterung für `Uint8List`, um eine Funktion zur Konvertierung von Bytes in einen Hex-String hinzuzufügen
extension Uint8ListExtention on Uint8List {
  /// Konvertiert die Bytes in einen Hexadezimal-String
  String bytesToHex() {
    return map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }
}
