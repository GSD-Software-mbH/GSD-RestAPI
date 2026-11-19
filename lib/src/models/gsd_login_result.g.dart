// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gsd_login_result.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

GsdLoginResult _$GsdLoginResultFromJson(Map<String, dynamic> json) =>
    $checkedCreate('GsdLoginResult', json, ($checkedConvert) {
      final val = GsdLoginResult(
        sessionId: $checkedConvert('sessionId', (v) => v as String),
        applications: $checkedConvert(
          'acls',
          (v) => v == null ? const [] : GsdLoginResult._applicationsFromAcls(v),
        ),
        isMdm2: $checkedConvert(
          'isMdm2',
          (v) => v as bool? ?? false,
          readValue: GsdLoginResult._readIsMdm2,
        ),
        user: $checkedConvert('user', (v) => v as Map<String, dynamic>?),
      );
      return val;
    }, fieldKeyMap: const {'applications': 'acls'});
