// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gsd_sync_container.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

GsdSyncContainer _$GsdSyncContainerFromJson(Map<String, dynamic> json) =>
    $checkedCreate('GsdSyncContainer', json, ($checkedConvert) {
      final val = GsdSyncContainer(
        containerId: $checkedConvert('containerId', (v) => v as String? ?? ''),
        revision: $checkedConvert('revision', (v) => ModelJson.intValue(v)),
        nextMarker: $checkedConvert('nextMarker', (v) => ModelJson.intValue(v)),
        contentId: $checkedConvert('contentId', (v) => v as String? ?? ''),
        readOnly: $checkedConvert('readOnly', (v) => v as bool? ?? false),
        count: $checkedConvert(
          'count',
          (v) => v == null ? 0 : ModelJson.intValue(v),
        ),
        startMarker: $checkedConvert(
          'startMarker',
          (v) => v == null ? 0 : ModelJson.intValue(v),
        ),
        endMarker: $checkedConvert(
          'endMarker',
          (v) => v == null ? 0 : ModelJson.intValue(v),
        ),
        hasMoreData: $checkedConvert('hasMoreData', (v) => v as bool? ?? false),
        classes: $checkedConvert(
          'classes',
          (v) => v == null ? const [] : GsdSyncContainer._classesFromJson(v),
        ),
        excluded: $checkedConvert(
          'excluded',
          (v) => v as List<dynamic>? ?? const [],
        ),
        deleted: $checkedConvert(
          'deleted',
          (v) => v as List<dynamic>? ?? const [],
        ),
      );
      return val;
    });

Map<String, dynamic> _$GsdSyncContainerToJson(GsdSyncContainer instance) =>
    <String, dynamic>{
      'containerId': instance.containerId,
      'contentId': instance.contentId,
      'readOnly': instance.readOnly,
      'count': instance.count,
      'revision': instance.revision,
      'startMarker': instance.startMarker,
      'endMarker': instance.endMarker,
      'nextMarker': instance.nextMarker,
      'hasMoreData': instance.hasMoreData,
      'classes': instance.classes.map((e) => e.toJson()).toList(),
      'excluded': instance.excluded,
      'deleted': instance.deleted,
    };
