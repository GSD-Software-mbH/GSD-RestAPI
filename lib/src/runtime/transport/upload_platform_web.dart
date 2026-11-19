import 'package:meta/meta.dart';

/// Upload-Fähigkeiten im Browser.
@internal
abstract final class UploadPlatform {
  /// Im Browser gibt es keinen Dateizugriff über einen Pfad.
  static const bool readsFilePaths = false;
}
