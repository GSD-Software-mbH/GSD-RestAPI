import 'package:equatable/equatable.dart';
import 'package:gsd_restapi/src/models/gsd_acl_entry.dart';
import 'package:gsd_restapi/src/models/model_json.dart';
import 'package:json_annotation/json_annotation.dart';

part 'gsd_login_result.g.dart';

/// Das Ergebnis von `v1.authentication.login`: `data` der Login-Antwort.
@JsonSerializable(createToJson: false)
class GsdLoginResult extends Equatable {
  /// Erstellt ein Login-Ergebnis.
  const GsdLoginResult({
    required this.sessionId,
    this.applications = const [],
    this.isMdm2 = false,
    this.user,
  });

  /// Liest das Ergebnis aus `data`; Pflicht ist nur `sessionId`.
  factory GsdLoginResult.fromJson(Map<String, Object?> json) =>
      _$GsdLoginResultFromJson(json);

  /// Session-ID für alle folgenden Aufrufe.
  final String sessionId;

  /// Die Anwendungen, auf die der Benutzer Zugriff hat, aus
  /// `acls.~Elements`; `null`-Einträge fallen weg.
  @JsonKey(name: 'acls', fromJson: _applicationsFromAcls)
  final List<GsdAclEntry> applications;

  /// Ob die Antwort ACLs enthielt (Anmeldung an einem MDM2-Server).
  @JsonKey(readValue: _readIsMdm2)
  final bool isMdm2;

  /// Das Benutzerobjekt (`~ObjectID`, `Name` …), wie es der Server liefert.
  final Map<String, Object?>? user;

  /// Ob der Benutzer Zugriff auf [application] hat, etwa `GSD-DFApp`.
  bool hasApplication(String application) =>
      applications.any((acl) => acl.application == application);

  @override
  List<Object?> get props => [sessionId, applications, isMdm2, user];

  // Ohne `~Elements` wirft der Fall `_`; `$checkedConvert` macht daraus
  // eine CheckedFromJsonException mit dem Schlüssel `acls`.
  static List<GsdAclEntry> _applicationsFromAcls(Object? acls) =>
      switch (acls) {
        null => const [],
        {'~Elements': final Object? elements} => ModelJson.list(
          elements,
          'acls.~Elements',
          GsdAclEntry.fromJson,
          skipNulls: true,
        ),
        _ => throw const FormatException('acls ohne ~Elements'),
      };

  static Object? _readIsMdm2(Map<dynamic, dynamic> json, String key) =>
      json['acls'] != null;
}
