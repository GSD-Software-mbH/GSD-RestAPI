// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gsd_check_service_result.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

GsdCheckServiceResult _$GsdCheckServiceResultFromJson(
  Map<String, dynamic> json,
) => $checkedCreate('GsdCheckServiceResult', json, ($checkedConvert) {
  final val = GsdCheckServiceResult(
    applicationName: $checkedConvert(
      'applicationName',
      (v) => v as String? ?? '',
    ),
    applicationVersion: $checkedConvert(
      'applicationVersion',
      (v) => v as String? ?? '',
      readValue: GsdCheckServiceResult._readApplicationVersion,
    ),
    databases: $checkedConvert(
      'webservice',
      (v) => v == null
          ? const []
          : GsdCheckServiceResult._databasesFromWebservice(v),
    ),
  );
  return val;
}, fieldKeyMap: const {'databases': 'webservice'});
