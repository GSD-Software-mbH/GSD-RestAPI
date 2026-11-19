// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gsd_version_info.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

GsdVersionInfo _$GsdVersionInfoFromJson(Map<String, dynamic> json) =>
    $checkedCreate(
      'GsdVersionInfo',
      json,
      ($checkedConvert) {
        final val = GsdVersionInfo(
          serviceVersion: $checkedConvert(
            'webserviceVersion',
            (v) => v as String? ?? '',
          ),
          structureChangeDate: $checkedConvert(
            'structureChangeDate',
            (v) => ModelJson.dateTimeOrNull(v),
          ),
          modules: $checkedConvert(
            'listOfModules',
            (v) => v == null ? const [] : GsdVersionInfo._modulesFromJson(v),
          ),
        );
        return val;
      },
      fieldKeyMap: const {
        'serviceVersion': 'webserviceVersion',
        'modules': 'listOfModules',
      },
    );
