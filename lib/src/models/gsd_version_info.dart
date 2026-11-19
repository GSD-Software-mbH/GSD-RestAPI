import 'package:equatable/equatable.dart';
import 'package:gsd_restapi/src/models/gsd_docuframe_module.dart';
import 'package:gsd_restapi/src/models/model_json.dart';
import 'package:json_annotation/json_annotation.dart';

part 'gsd_version_info.g.dart';

/// Versionsinformationen des Webservice, das Ergebnis von
/// `v1.service.getVersionInfo`.
@JsonSerializable(createToJson: false)
class GsdVersionInfo extends Equatable {
  /// Erstellt Versionsinformationen.
  const GsdVersionInfo({
    this.serviceVersion = '',
    this.structureChangeDate,
    this.modules = const [],
  });

  /// Liest die Versionsinformationen aus `data`.
  factory GsdVersionInfo.fromJson(Map<String, Object?> json) =>
      _$GsdVersionInfoFromJson(json);

  /// Version des Webservice im Format `x.y.z` (`webserviceVersion`).
  @JsonKey(name: 'webserviceVersion', defaultValue: '')
  final String serviceVersion;

  /// Wann sich die Struktur der Datenbank zuletzt geändert hat; `""` ergibt
  /// `null`.
  @JsonKey(fromJson: ModelJson.dateTimeOrNull)
  final DateTime? structureChangeDate;

  /// Die installierten Module mit ihren Versionen (`listOfModules`).
  @JsonKey(name: 'listOfModules', fromJson: _modulesFromJson)
  final List<GsdDocuframeModule> modules;

  @override
  List<Object?> get props => [serviceVersion, structureChangeDate, modules];

  static List<GsdDocuframeModule> _modulesFromJson(Object? json) =>
      ModelJson.list(json, 'listOfModules', GsdDocuframeModule.fromJson);
}
