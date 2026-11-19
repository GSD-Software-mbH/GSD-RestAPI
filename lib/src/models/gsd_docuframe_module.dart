import 'package:equatable/equatable.dart';
import 'package:json_annotation/json_annotation.dart';

part 'gsd_docuframe_module.g.dart';

/// Ein Modul einer DOCUframe-Datenbank mit seiner Version.
///
/// Module erweitern die Funktionalität der REST-API und haben
/// spezifische Versionsnummern für Kompatibilitätsprüfungen.
///
/// Wird verwendet für:
/// - Feature-Verfügbarkeit-Checks
/// - Versions-Kompatibilität zwischen Client und Server
/// - Funktions-spezifische API-Aufrufe
@JsonSerializable(createToJson: false)
class GsdDocuframeModule extends Equatable {
  /// Erstellt ein Modul [name] in der Version [version].
  const GsdDocuframeModule(this.name, this.version);

  /// Liest ein Modul aus `{moduleName, moduleVersion}`; fehlende Werte
  /// ergeben `''`.
  factory GsdDocuframeModule.fromJson(Map<String, Object?> json) =>
      _$GsdDocuframeModuleFromJson(json);

  /// Name des Moduls
  ///
  /// Eindeutige Identifikation des Moduls (z.B. "Core", "Email", "Calendar").
  @JsonKey(name: 'moduleName', defaultValue: '')
  final String name;

  /// Version des Moduls
  ///
  /// Versionsnummer im Format "x.y.z" für Kompatibilitätsprüfungen.
  @JsonKey(name: 'moduleVersion', defaultValue: '')
  final String version;

  @override
  List<Object?> get props => [name, version];
}
