import 'package:json_annotation/json_annotation.dart';

part 'gsd_objects_by_id_request.g.dart';

/// Ein Eintrag im Body von `POST v3/objectdata/byid`: die Objekte [ids] einer
/// Klasse [classId].
@JsonSerializable(createFactory: false)
class GsdObjectsByIdRequest {
  /// Erstellt einen Eintrag für die Objekte [ids] der Klasse [classId].
  ///
  /// [context] wird als String gesendet, auch `null`: Der Server bekommt dann
  /// `"null"`, wie bisher von der App.
  const GsdObjectsByIdRequest({
    required this.classId,
    required this.ids,
    String? context,
  }) : context = '$context';

  /// Klassen-ID der Objekte.
  final int classId;

  /// Art der Abfrage; bei `byid` immer leer.
  String get type => '';

  /// Kontext der Abfrage, etwa `edit`; `"null"` ohne Kontext.
  final String context;

  /// Objekt-IDs innerhalb der Klasse.
  final List<int> ids;

  /// Der Eintrag als JSON, in der Schlüsselreihenfolge der Felder.
  Map<String, Object?> toJson() => _$GsdObjectsByIdRequestToJson(this);
}
