import 'package:meta/meta.dart';

/// Upload-Fähigkeiten auf der VM (Mobile, Desktop).
@internal
abstract final class UploadPlatform {
  /// `http.MultipartFile.fromPath` liest die Datei über `dart:io`.
  static const bool readsFilePaths = true;
}
