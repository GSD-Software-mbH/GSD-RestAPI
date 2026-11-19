import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/v3/gsd_v3_file_api.dart';
import 'package:gsd_restapi/src/v3/gsd_v3_model_api.dart';
import 'package:gsd_restapi/src/v3/gsd_v3_object_data_api.dart';
import 'package:gsd_restapi/src/v3/gsd_v3_system_api.dart';
import 'package:gsd_restapi/src/v3/gsd_v3_view_api.dart';
import 'package:meta/meta.dart';

/// Öffentliche Gruppen der nativen V3-API.
///
/// V3 bündelt die fachlichen Endpunkte in fünf Gruppen: [model]
/// (`model/structure`), [system] (`versionInfo`, `appConfig`, `appTheme`),
/// [view] (`view/load`, `view/action`), [objectData] (`objectdata/byid`,
/// `byQuery`, `byParentObject`) und [file] (`file/{oid}`, Binärdownload).
/// Alle Requests laufen unter [GsdApiVersion.v3] mit dem `operationId`-Präfix
/// `v3.…`.
///
/// Der Login gehört bewusst nicht dazu: Er liegt weiterhin als `v2/login`
/// (`GET v2/login/key` + `POST v2/login`) im `SessionCoordinator`.
///
/// Alle Gruppen verwenden denselben Runtime und Sessionzustand wie V1 und
/// laufen niemals über `GsdRawApi`, `customRequest` oder den Legacy-Manager.
class GsdV3Api {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV3Api.internal(ApiRuntime runtime)
    : model = GsdV3ModelApi.internal(runtime),
      system = GsdV3SystemApi.internal(runtime),
      view = GsdV3ViewApi.internal(runtime),
      objectData = GsdV3ObjectDataApi.internal(runtime),
      file = GsdV3FileApi.internal(runtime);

  /// Modelloperationen (`model/structure`).
  final GsdV3ModelApi model;

  /// Systemoperationen (`versionInfo`, `appConfig`, `appTheme`).
  final GsdV3SystemApi system;

  /// Viewoperationen (`view/load`, `view/action`).
  final GsdV3ViewApi view;

  /// Objektdatenoperationen (`objectdata/...`).
  final GsdV3ObjectDataApi objectData;

  /// Dateioperationen (`file/{oid}`).
  final GsdV3FileApi file;
}
