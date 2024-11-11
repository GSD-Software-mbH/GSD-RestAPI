import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

extension StringExtensions on String {
  // Funktion zur Entschlüsselung des öffentlichen Schlüssels
  RSAPublicKey parsePublicKeyFromPem() {
    // Entferne Header und Footer und dekodiere den Base64 PEM-Block
    final pemLines = split('\n');
    final base64String = pemLines.where((line) => line.isNotEmpty && !line.startsWith('---')).join();
    final bytes = base64.decode(base64String);

    // Parsing der ASN.1-Struktur
    final asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    // Innerhalb der Top-Level-Sequenz befindet sich der Algorithmus-Identifier und der öffentliche Schlüssel
    final publicKeyBitString = topLevelSeq.elements![1] as ASN1BitString;

    // Extrahiere den Inhalt des BitStrings (das ist der eigentliche öffentliche Schlüssel)
    final publicKeyBytes = publicKeyBitString.stringValues;

    // Parsing der Public-Key-Struktur (die in den BitString-Daten enthalten ist)
    final publicKeyAsn1Parser = ASN1Parser(Uint8List.fromList(publicKeyBytes!));
    final publicKeySeq = publicKeyAsn1Parser.nextObject() as ASN1Sequence;

    // Modulus (n) und Exponent (e) extrahieren
    final ASN1Integer modulusASN1 = publicKeySeq.elements![0] as ASN1Integer;
    final ASN1Integer exponentASN1 = publicKeySeq.elements![1] as ASN1Integer;

    // Modulus und Exponent in BigInt umwandeln
    final modulusBigInt = BigInt.parse(modulusASN1.valueBytes!.bytesToHex(), radix: 16);
    final exponentBigInt = BigInt.parse(exponentASN1.valueBytes!.bytesToHex(), radix: 16);

    // Erstelle den RSAPublicKey
    return RSAPublicKey(modulusBigInt, exponentBigInt);
  }
}

extension RSAPublicKeyExtention on RSAPublicKey {
  // Funktion, um den RSA Public Key ins PEM-Format zu konvertieren
  String encodeToPem() {
    // Erstelle ASN.1-Objekte für Modulus und Exponent
    final asn1Modulus = ASN1Integer(modulus!);
    final asn1Exponent = ASN1Integer(exponent!);

    // Erstelle die ASN.1-Sequenz, die den Modulus und Exponent enthält
    final asn1Seq = ASN1Sequence();
    asn1Seq.add(asn1Modulus);
    asn1Seq.add(asn1Exponent);

    // Kodieren der publicKey-Bytes in ein BitString
    final publicKeyBytes = asn1Seq.encode();

    // Verpakke die publicKeyBytes in einen BitString
    final publicKeyBitString = ASN1BitString(stringValues: publicKeyBytes);

    // Erstelle die Algorithmen-Sequenz
    final algorithmSeq = ASN1Sequence();
    algorithmSeq.add(ASN1ObjectIdentifier.fromName("rsaEncryption"));
    algorithmSeq.add(ASN1Null());

    // Erstelle die oberste ASN.1-Sequenz, die den Algorithmus und den Schlüssel enthält
    final topLevelSeq = ASN1Sequence();
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeyBitString);

    // Jetzt sollte die Top-Level-Sequenz korrekt kodiert werden
    final base64Key = base64Encode(topLevelSeq.encode());

    // PEM-Format erstellen
    final pemString = """
    -----BEGIN PUBLIC KEY-----
    ${_chunked(base64Key, 64)}
    -----END PUBLIC KEY-----
    """;

    return pemString;
  }

  String _chunked(String str, int chunkSize) {
    final RegExp pattern = RegExp('.{1,$chunkSize}');
    return pattern.allMatches(str).map((m) => m.group(0)).join('\r\n');
  }
}

extension Uint8ListExtention on Uint8List {
  String bytesToHex() {
    return map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }
}
