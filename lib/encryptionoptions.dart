part of 'gsd_encryption.dart';

class EncryptionOptions {

  String get rsaPrivateKeyFilePath {
    return _rsaPrivateKeyFilePath;
  }

  String get rsaPublicKeyFilePath {
    return _rsaPublicKeyFilePath;
  }

  List<int> get aesKeyBytes {
    return _aesKeyBytes;
  }

  String _rsaPublicKeyFilePath = "";
  String _rsaPrivateKeyFilePath = "";
  List<int> _aesKeyBytes = [];

  EncryptionOptions({String rsaPrivateKeyFilePath = "", String rsaPublicKeyFilePath = "", List<int> aesKeyBytes = const []}) {
    _rsaPrivateKeyFilePath = rsaPrivateKeyFilePath;
    _rsaPublicKeyFilePath = rsaPublicKeyFilePath;
    _aesKeyBytes = aesKeyBytes;
  }
}