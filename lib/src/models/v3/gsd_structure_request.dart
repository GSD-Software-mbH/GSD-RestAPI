import 'package:json_annotation/json_annotation.dart';

part 'gsd_structure_request.g.dart';

/// Ein Eintrag im Body von `POST v3/model/structure`.
///
/// Fragt die Modellstruktur ab [className] ab; die `skip…`-Schalter blenden
/// Teile der Antwort aus.
@JsonSerializable(createFactory: false)
class GsdStructureRequest {
  /// Erstellt einen Eintrag für [className].
  const GsdStructureRequest({
    required this.className,
    required this.skipDerivedClasses,
    required this.skipMembers,
    required this.skipBaseMembers,
    required this.skipIndices,
    required this.skipValueMapping,
  });

  /// Klasse, ab der die Struktur geliefert wird, etwa `Object`.
  final String className;

  /// Abgeleitete Klassen weglassen.
  final bool skipDerivedClasses;

  /// Member weglassen.
  final bool skipMembers;

  /// Member der Basisklassen weglassen.
  final bool skipBaseMembers;

  /// Indizes weglassen.
  final bool skipIndices;

  /// Wertzuordnungen weglassen.
  final bool skipValueMapping;

  /// Der Eintrag als JSON, in der Schlüsselreihenfolge der Felder.
  Map<String, Object?> toJson() => _$GsdStructureRequestToJson(this);
}
