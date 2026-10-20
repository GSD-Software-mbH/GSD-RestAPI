part of '../docuframe_api.dart';

/// Öffentliche Gruppen der nativen V3-API.
///
/// V3 bündelt die fachlichen Endpunkte in fünf Gruppen: [model]
/// (`model/structure`), [system] (`versionInfo`, `appConfig`, `appTheme`),
/// [view] (`view/load`, `view/action`), [objectData] (`objectdata/byid`,
/// `byQuery`, `byParentObject`) und [file] (`file/{oid}`, Binärdownload).
/// Alle Requests laufen unter [ApiVersion.v3] mit dem `operationId`-Präfix
/// `v3.…`.
///
/// Der Login gehört bewusst nicht dazu: Er liegt weiterhin als `v2/login`
/// (`GET v2/login/key` + `POST v2/login`) im `SessionCoordinator`.
///
/// Alle Gruppen verwenden denselben Runtime und Sessionzustand wie V1 und
/// laufen niemals über `RawApi`, `customRequest` oder den Legacy-Manager.
class DocuframeV3Api {
  V3ModelApi model;
  V3SystemApi system;
  V3ViewApi view;
  V3ObjectDataApi objectData;
  V3FileApi file;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  DocuframeV3Api.internal(ApiRuntime runtime)
    : model = V3ModelApi.internal(runtime),
      system = V3SystemApi.internal(runtime),
      view = V3ViewApi.internal(runtime),
      objectData = V3ObjectDataApi.internal(runtime),
      file = V3FileApi.internal(runtime);
}
