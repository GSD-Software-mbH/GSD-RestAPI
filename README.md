# Flutter Encryption

Dieses Paket bietet AES- und RSA-Verschlüsselungs- und Entschlüsselungsfunktionen für Flutter-Anwendungen und erleichtert die sichere Speicherung und Verarbeitung von sensiblen Daten. Es umfasst Funktionen zur Verwaltung von Schlüsseln (sowohl symmetrische als auch asymmetrische) und zur sicheren Speicherung im Gerät.

## Installation

Fügen Sie das Paket in Ihrer `pubspec.yaml` hinzu:

```yaml
dependencies:
  encryption:
    git:
      url: http://gsd-dfdev:8080/tfs/DefaultCollection/Flutter%20Encryption/_git/Flutter%20Encryption
      ref: master
```

Führen Sie anschließend `flutter pub get` aus, um das Paket zu installieren.

## Nutzung

### Initialisieren des EncryptionManager

Erstellen Sie eine Instanz des `EncryptionManager` für die Verschlüsselungs- und Entschlüsselungsfunktionen:

```dart
import 'package:encryption/encryption.dart';

final encryptionManager = EncryptionManager();
```

### AES-Verschlüsselung und -Entschlüsselung

1. **AES-Schlüssel initialisieren**: Rufen Sie `initializeAESKey()` auf, um den AES-Schlüssel zu generieren und sicher zu speichern.
2. **Text verschlüsseln**:
   ```dart
   String encryptedText = await encryptionManager.encryptAES('Ihr Klartext');
   ```
3. **Text entschlüsseln**:
   ```dart
   String decryptedText = await encryptionManager.decryptAES(encryptedText);
   ```

### RSA-Verschlüsselung und -Entschlüsselung

1. **RSA-Schlüsselpaar initialisieren**: Rufen Sie `initializeRSAKeyPair()` auf, um ein RSA-Schlüsselpaar zu generieren.
2. **Text verschlüsseln**:
   ```dart
   String encryptedText = await encryptionManager.encryptRSA('Ihr Klartext');
   ```
3. **Text entschlüsseln**:
   ```dart
   String decryptedText = await encryptionManager.decryptRSA(encryptedText);
   ```

### Verwendung der PEM-Funktionen

Um einen RSA-Schlüssel im PEM-Format zu parsen oder zu exportieren, nutzen Sie die Erweiterungen:

1. **PEM-Format in `RSAPublicKey` konvertieren**:
   ```dart
   RSAPublicKey publicKey = 'Ihr PEM-Schlüssel'.parsePublicKeyFromPem();
   ```
2. **`RSAPublicKey` ins PEM-Format konvertieren**:
   ```dart
   String pemString = publicKey.encodeToPem();
   ```

## Hinweise

- **AES** wird im CBC-Modus mit zufälligen IVs (Initialisierungsvektoren) verwendet, um die Sicherheit zu erhöhen.
- Die Schlüsseldaten werden mit `flutter_secure_storage` sicher auf dem Gerät gespeichert.

Dieses Paket ermöglicht die einfache Integration von Verschlüsselung in Ihre Flutter-Anwendung und bietet Schutz für sensible Informationen.