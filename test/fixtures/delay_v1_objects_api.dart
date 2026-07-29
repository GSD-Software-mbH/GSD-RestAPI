import 'package:gsd_restapi/docuframe_api.dart';

/// Test-Fixture: V1ObjectsApi mit simulierten Netzwerk-Delays.
///
/// Überschreibt nur Methoden, die ein Delay brauchen (z.B. postAction, patchObject).
/// Andere Methoden werden nicht verzögert.
///
/// Verwendung:
/// ```dart
/// final api = DelayDocuframeApi(configuration: config);
/// await api.v1.objects.postAction('MyClass');  // 500ms Delay
/// ```
class DelayV1ObjectsApi extends V1ObjectsApi {
  /// Standard-Delays für verschiedene Operationen (in ms).
  static const int _defaultPostActionDelay = 500;
  static const int _defaultPatchObjectDelay = 300;

  DelayV1ObjectsApi(super.runtime) : super.internal();

  @override
  Future<RestApiResponse> postAction(
    String className, {
    String query = '',
    int page = 0,
    int? perPage,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) async {
    // Simulate 500ms network delay
    await Future.delayed(Duration(milliseconds: _defaultPostActionDelay));
    return super.postAction(
      className,
      query: query,
      page: page,
      perPage: perPage,
      serialization: serialization,
      actions: actions,
      rightsControlKey: rightsControlKey,
    );
  }

  @override
  Future<RestApiResponse> patchObject(
    String objectOid,
    String body, {
    int storeMode = 0,
    int storeSecurityPolice = 0,
    String serialization = '',
    String actions = '',
    String rightsControlKey = '',
  }) async {
    // Simulate 300ms network delay
    await Future.delayed(Duration(milliseconds: _defaultPatchObjectDelay));
    return super.patchObject(
      objectOid,
      body,
      storeMode: storeMode,
      storeSecurityPolice: storeSecurityPolice,
      serialization: serialization,
      actions: actions,
      rightsControlKey: rightsControlKey,
    );
  }
}
