import 'package:json_annotation/json_annotation.dart';

part 'gsd_objects_by_parent_request.g.dart';

/// Ein Eintrag im Body von `POST v3/objectdata/byParentObject`: die Objekte
/// im Member [member] des Elternobjekts [parentOid].
///
/// Optionale Felder, die `null` sind, fehlen im JSON. Die `se…`-Felder sind
/// die Volltextsuche des Servers; ohne sie sucht er nicht.
@JsonSerializable(createFactory: false)
class GsdObjectsByParentRequest {
  /// Erstellt einen Eintrag für [member] von [parentOid].
  const GsdObjectsByParentRequest({
    required this.parentOid,
    required this.member,
    required this.idList,
    this.context,
    this.query,
    this.order,
    this.seFulltext,
    this.seFulltextConcept,
    this.seFulltextStem,
    this.seFulltextTypo,
    this.seTextContent,
    this.seTextContentConcept,
    this.seTextContentStem,
    this.seTextContentTypo,
    this.seSortByScore,
    this.seFulltextCombineAnd,
    this.seCreateTimeFrom,
    this.seCreateTimeTo,
  });

  /// OID des Elternobjekts.
  @JsonKey(name: 'parentOID')
  final String parentOid;

  /// Member des Elternobjekts, etwa `Dokumente`.
  final String member;

  /// Kontext der Abfrage, etwa `edit`.
  @JsonKey(includeIfNull: false)
  final String? context;

  /// `true`: nur die IDs der Objekte (`classId,objectId,storeCount`), keine
  /// Felder.
  final bool idList;

  /// DOCUframe-Abfrage, die die Objekte filtert.
  @JsonKey(includeIfNull: false)
  final String? query;

  /// Sortierung, etwa `Name ASC`.
  @JsonKey(includeIfNull: false)
  final String? order;

  /// Suchtext in den Metadaten.
  @JsonKey(includeIfNull: false)
  final String? seFulltext;

  /// Suchkonzept für [seFulltext], als Zahl oder Name (Server: `FTC_ALL`).
  @JsonKey(includeIfNull: false)
  final Object? seFulltextConcept;

  /// Wortstämme für [seFulltext] suchen.
  @JsonKey(includeIfNull: false)
  final bool? seFulltextStem;

  /// Tippfehler in [seFulltext] tolerieren.
  @JsonKey(includeIfNull: false)
  final bool? seFulltextTypo;

  /// Suchtext im Inhalt der Dokumente.
  @JsonKey(includeIfNull: false)
  final String? seTextContent;

  /// Suchkonzept für [seTextContent], als Zahl oder Name.
  @JsonKey(includeIfNull: false)
  final Object? seTextContentConcept;

  /// Wortstämme für [seTextContent] suchen.
  @JsonKey(includeIfNull: false)
  final bool? seTextContentStem;

  /// Tippfehler in [seTextContent] tolerieren.
  @JsonKey(includeIfNull: false)
  final bool? seTextContentTypo;

  /// Nach Treffergüte sortieren (Server: `true`).
  @JsonKey(includeIfNull: false)
  final bool? seSortByScore;

  /// Die Suchbegriffe in [seFulltext] mit UND verknüpfen.
  @JsonKey(includeIfNull: false)
  final bool? seFulltextCombineAnd;

  /// Frühester Erstellzeitpunkt, als Unix-Zeitstempel oder String.
  @JsonKey(includeIfNull: false)
  final Object? seCreateTimeFrom;

  /// Spätester Erstellzeitpunkt, als Unix-Zeitstempel oder String.
  @JsonKey(includeIfNull: false)
  final Object? seCreateTimeTo;

  /// Der Eintrag als JSON, in der Schlüsselreihenfolge der Felder.
  Map<String, Object?> toJson() => _$GsdObjectsByParentRequestToJson(this);
}
