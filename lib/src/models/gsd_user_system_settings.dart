import 'package:equatable/equatable.dart';
import 'package:gsd_restapi/src/models/model_json.dart';
import 'package:iso8601_duration/iso8601_duration.dart';
import 'package:json_annotation/json_annotation.dart';

part 'gsd_user_system_settings.g.dart';

/// Die Systemeinstellungen des angemeldeten Benutzers, das Ergebnis von
/// `v1.settings.getUserSystemSettings`.
///
/// Fehlende Werte ergeben `false`, `0`, `''` bzw. eine leere Map.
@JsonSerializable(createToJson: false)
class GsdUserSystemSettings extends Equatable {
  /// Erstellt Systemeinstellungen.
  const GsdUserSystemSettings({
    this.autoDocReadOnOpen = false,
    this.noPromptInsertNewDocsUserFolders = false,
    this.noPromptInsertNewDocsGlobalFolders = false,
    this.dateDefaultReminderTimeSpan = const Duration(minutes: 5),
    this.userRights = 0,
    this.nextNewDocumentsCount = 0,
    this.missedCallsCount = 0,
    this.dateUserObjectName = '',
    this.eventSettings = const {},
  });

  /// Liest die Einstellungen aus `data`.
  factory GsdUserSystemSettings.fromJson(Map<String, Object?> json) =>
      _$GsdUserSystemSettingsFromJson(json);

  /// Dokumente beim Öffnen als gelesen markieren.
  @JsonKey(defaultValue: false)
  final bool autoDocReadOnOpen;

  /// Neue Dokumente ohne Rückfrage in Benutzerordner einfügen.
  @JsonKey(defaultValue: false)
  final bool noPromptInsertNewDocsUserFolders;

  /// Neue Dokumente ohne Rückfrage in globale Ordner einfügen.
  @JsonKey(defaultValue: false)
  final bool noPromptInsertNewDocsGlobalFolders;

  /// Standard-Erinnerungszeit vor einem Termin. Der Server liefert eine
  /// ISO-8601-Dauer (`PT15M`); ohne Wert gelten 5 Minuten. Jahre zählen zu
  /// 365, Monate zu 30 Tagen.
  @JsonKey(fromJson: _durationFromJson)
  final Duration dateDefaultReminderTimeSpan;

  /// Benutzerrechte als Bitmaske.
  @JsonKey(fromJson: ModelJson.intValue)
  final int userRights;

  /// Anzahl der neuen Dokumente des Benutzers.
  @JsonKey(fromJson: ModelJson.intValue)
  final int nextNewDocumentsCount;

  /// Anzahl der verpassten Anrufe.
  @JsonKey(fromJson: ModelJson.intValue)
  final int missedCallsCount;

  /// Benutzer oder Benutzergruppe, deren Termine der Kalender zeigt; leer
  /// heißt der angemeldete Benutzer.
  @JsonKey(defaultValue: '')
  final String dateUserObjectName;

  /// Ereigniseinstellungen aus den Event-Makros.
  final Map<String, Object?> eventSettings;

  @override
  List<Object?> get props => [
    autoDocReadOnOpen,
    noPromptInsertNewDocsUserFolders,
    noPromptInsertNewDocsGlobalFolders,
    dateDefaultReminderTimeSpan,
    userRights,
    nextNewDocumentsCount,
    missedCallsCount,
    dateUserObjectName,
    eventSettings,
  ];

  static Duration _durationFromJson(Object? json) {
    if (json == null || json == '') {
      return const Duration(minutes: 5);
    }
    final duration = ISODurationConverter().parseString(
      isoDurationString: json as String,
    );
    final days =
        (duration.year ?? 0) * 365 +
        (duration.month ?? 0) * 30 +
        (duration.week ?? 0) * 7 +
        (duration.day ?? 0);
    final seconds =
        days * Duration.secondsPerDay +
        (duration.hour ?? 0) * Duration.secondsPerHour +
        (duration.minute ?? 0) * Duration.secondsPerMinute +
        (duration.seconds ?? 0);
    return Duration(
      microseconds: (seconds * Duration.microsecondsPerSecond).round(),
    );
  }
}
