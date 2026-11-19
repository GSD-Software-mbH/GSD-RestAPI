import 'package:json_annotation/json_annotation.dart';

part 'gsd_view_load_request.g.dart';

/// Ein Eintrag im Body von `POST v3/view/load`: die View [viewName].
@JsonSerializable(createFactory: false)
class GsdViewLoadRequest {
  /// Erstellt einen Eintrag für die View [viewName].
  const GsdViewLoadRequest({
    required this.viewName,
    this.className = '',
    this.context = '',
  });

  /// Art der Abfrage; bei `view/load` immer `"1"`.
  String get type => '1';

  /// Name der View, etwa `edit`.
  final String viewName;

  /// Klasse, zu der die View gehört; leer für eine klassenlose View.
  final String className;

  /// Kontext der View, etwa `mobile`; leer ohne Kontext.
  final String context;

  /// Der Eintrag als JSON, in der Schlüsselreihenfolge der Felder.
  Map<String, Object?> toJson() => _$GsdViewLoadRequestToJson(this);
}
