part of 'gsd_restapi.dart';

class RestApiUploadFile {
  String name;
  final String? path;
  final Uint8List? bytes;

  RestApiUploadFile({required this.name, this.path, this.bytes})
    : assert(
        (path != null && bytes == null) || (path == null && bytes != null),
        'Either path or bytes must be provided, but not both',
      );

  // Constructor for mobile platforms (Android, iOS)
  RestApiUploadFile.fromPath({required String this.path})
    : bytes = null,
      name = path.split(RegExp(r'[/\\]')).last;

  // Constructor for web platform
  RestApiUploadFile.fromBytes({
    required this.name,
    required Uint8List this.bytes,
  }) : path = null;

  bool get isPath => path != null;
  bool get isBytes => bytes != null;
}
