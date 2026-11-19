// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gsd_acl_entry.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

GsdAclEntry _$GsdAclEntryFromJson(Map<String, dynamic> json) => $checkedCreate(
  'GsdAclEntry',
  json,
  ($checkedConvert) {
    final val = GsdAclEntry(
      oid: $checkedConvert('Oid', (v) => v as String),
      status: $checkedConvert('Status', (v) => (v as num).toInt()),
      userName: $checkedConvert('UserName', (v) => v as String),
      licenseKey: $checkedConvert('LicenseKey', (v) => v as String),
      licenseLevel: $checkedConvert('LicenseLevel', (v) => v as String?),
      parallelConnections: $checkedConvert(
        'ParallelConnections',
        (v) => (v as num).toDouble(),
      ),
      tfaActivated: $checkedConvert('TFAActivated', (v) => v as bool),
      tfaConfirmed: $checkedConvert('TFAConfirmed', (v) => v as bool),
      application: $checkedConvert('Application', (v) => v as String),
      addOns: $checkedConvert(
        'addOns',
        (v) => (v as List<dynamic>?)?.map((e) => e as String).toList() ?? [],
        readValue: GsdAclEntry._readAddOns,
      ),
      deviceID: $checkedConvert('DeviceID', (v) => v as String?),
    );
    return val;
  },
  fieldKeyMap: const {
    'oid': 'Oid',
    'status': 'Status',
    'userName': 'UserName',
    'licenseKey': 'LicenseKey',
    'licenseLevel': 'LicenseLevel',
    'parallelConnections': 'ParallelConnections',
    'tfaActivated': 'TFAActivated',
    'tfaConfirmed': 'TFAConfirmed',
    'application': 'Application',
    'deviceID': 'DeviceID',
  },
);
