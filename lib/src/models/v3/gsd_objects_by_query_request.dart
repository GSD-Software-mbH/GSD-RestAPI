import 'package:json_annotation/json_annotation.dart';

part 'gsd_objects_by_query_request.g.dart';

/// Ein Eintrag im Body von `POST v3/objectdata/byQuery`: die Objekte der
/// Klasse [className], auf die [query] passt.
@JsonSerializable(createFactory: false)
class GsdObjectsByQueryRequest {
  /// Erstellt einen Eintrag für [className]; ohne [query] alle Objekte.
  const GsdObjectsByQueryRequest({required this.className, this.query = ''});

  /// Name der Klasse, etwa `Dokument`.
  final String className;

  /// Art der Abfrage; bei `byQuery` immer `"0"`.
  String get type => '0';

  /// DOCUframe-Abfrage, etwa `Name=Test`; leer für alle Objekte.
  final String query;

  /// Der Eintrag als JSON, in der Schlüsselreihenfolge der Felder.
  Map<String, Object?> toJson() => _$GsdObjectsByQueryRequestToJson(this);
}
