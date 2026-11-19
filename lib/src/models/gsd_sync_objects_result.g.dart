// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gsd_sync_objects_result.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

GsdSyncObjectsResult _$GsdSyncObjectsResultFromJson(
  Map<String, dynamic> json,
) => $checkedCreate('GsdSyncObjectsResult', json, ($checkedConvert) {
  final val = GsdSyncObjectsResult(
    allContainers: $checkedConvert(
      'allContainers',
      (v) =>
          (v as List<dynamic>?)?.map((e) => e as String).toList() ?? const [],
    ),
    containers: $checkedConvert(
      'containers',
      (v) => v == null ? const {} : GsdSyncObjectsResult._containersFromJson(v),
      readValue: GsdSyncObjectsResult._readContainers,
    ),
    data: $checkedConvert(
      'data',
      (v) => v as Map<String, dynamic>? ?? const {},
      readValue: GsdSyncObjectsResult._readData,
    ),
  );
  return val;
});
