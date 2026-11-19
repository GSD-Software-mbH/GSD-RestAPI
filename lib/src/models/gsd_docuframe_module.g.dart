// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gsd_docuframe_module.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

GsdDocuframeModule _$GsdDocuframeModuleFromJson(Map<String, dynamic> json) =>
    $checkedCreate(
      'GsdDocuframeModule',
      json,
      ($checkedConvert) {
        final val = GsdDocuframeModule(
          $checkedConvert('moduleName', (v) => v as String? ?? ''),
          $checkedConvert('moduleVersion', (v) => v as String? ?? ''),
        );
        return val;
      },
      fieldKeyMap: const {'name': 'moduleName', 'version': 'moduleVersion'},
    );
