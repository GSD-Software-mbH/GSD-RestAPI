part of '../docuframe_api.dart';

/// Öffentliche Gruppen der nativen V2-API.
///
/// Alle Gruppen verwenden denselben Runtime und Sessionzustand wie V1 und
/// laufen niemals über `RawApi`, `customRequest` oder den Legacy-Manager.
class DocuframeV2Api {
  V2ModelApi model;
  V2SystemApi system;
  V2ViewApi view;
  V2ObjectDataApi objectData;
  V2FileApi file;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  DocuframeV2Api.internal(ApiRuntime runtime)
    : model = V2ModelApi.internal(runtime),
      system = V2SystemApi.internal(runtime),
      view = V2ViewApi.internal(runtime),
      objectData = V2ObjectDataApi.internal(runtime),
      file = V2FileApi.internal(runtime);
}
