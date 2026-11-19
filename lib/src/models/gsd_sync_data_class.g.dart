// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gsd_sync_data_class.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

GsdSyncDataClass _$GsdSyncDataClassFromJson(Map<String, dynamic> json) =>
    $checkedCreate('GsdSyncDataClass', json, ($checkedConvert) {
      final val = GsdSyncDataClass(
        className: $checkedConvert('className', (v) => v as String? ?? ''),
        count: $checkedConvert('count', (v) => ModelJson.intValue(v)),
        header: $checkedConvert(
          'header',
          (v) => (v as List<dynamic>?)?.map((e) => e as String).toList() ?? [],
        ),
        data: $checkedConvert(
          'data',
          (v) =>
              (v as List<dynamic>?)?.map((e) => e as List<dynamic>).toList() ??
              [],
        ),
      );
      return val;
    });

Map<String, dynamic> _$GsdSyncDataClassToJson(GsdSyncDataClass instance) =>
    <String, dynamic>{
      'className': instance.className,
      'count': instance.count,
      'header': instance.header,
      'data': instance.data,
    };
