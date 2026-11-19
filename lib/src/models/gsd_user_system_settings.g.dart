// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gsd_user_system_settings.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

GsdUserSystemSettings _$GsdUserSystemSettingsFromJson(
  Map<String, dynamic> json,
) => $checkedCreate('GsdUserSystemSettings', json, ($checkedConvert) {
  final val = GsdUserSystemSettings(
    autoDocReadOnOpen: $checkedConvert(
      'autoDocReadOnOpen',
      (v) => v as bool? ?? false,
    ),
    noPromptInsertNewDocsUserFolders: $checkedConvert(
      'noPromptInsertNewDocsUserFolders',
      (v) => v as bool? ?? false,
    ),
    noPromptInsertNewDocsGlobalFolders: $checkedConvert(
      'noPromptInsertNewDocsGlobalFolders',
      (v) => v as bool? ?? false,
    ),
    dateDefaultReminderTimeSpan: $checkedConvert(
      'dateDefaultReminderTimeSpan',
      (v) => v == null
          ? const Duration(minutes: 5)
          : GsdUserSystemSettings._durationFromJson(v),
    ),
    userRights: $checkedConvert(
      'userRights',
      (v) => v == null ? 0 : ModelJson.intValue(v),
    ),
    nextNewDocumentsCount: $checkedConvert(
      'nextNewDocumentsCount',
      (v) => v == null ? 0 : ModelJson.intValue(v),
    ),
    missedCallsCount: $checkedConvert(
      'missedCallsCount',
      (v) => v == null ? 0 : ModelJson.intValue(v),
    ),
    dateUserObjectName: $checkedConvert(
      'dateUserObjectName',
      (v) => v as String? ?? '',
    ),
    eventSettings: $checkedConvert(
      'eventSettings',
      (v) => v as Map<String, dynamic>? ?? const {},
    ),
  );
  return val;
});
