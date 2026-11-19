// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gsd_two_factor_secret.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

GsdTwoFactorSecret _$GsdTwoFactorSecretFromJson(Map<String, dynamic> json) =>
    $checkedCreate('GsdTwoFactorSecret', json, ($checkedConvert) {
      final val = GsdTwoFactorSecret(
        isActivated: $checkedConvert('isActivated', (v) => v as bool? ?? false),
        isConfirmed: $checkedConvert('isConfirmed', (v) => v as bool? ?? false),
        status: $checkedConvert(
          '2faStatus',
          (v) =>
              $enumDecodeNullable(
                _$GsdTwoFactorStatusEnumMap,
                v,
                unknownValue: GsdTwoFactorStatus.na,
              ) ??
              GsdTwoFactorStatus.na,
        ),
      );
      return val;
    }, fieldKeyMap: const {'status': '2faStatus'});

const _$GsdTwoFactorStatusEnumMap = {
  GsdTwoFactorStatus.na: 0,
  GsdTwoFactorStatus.deactivated: 1,
  GsdTwoFactorStatus.optional: 2,
  GsdTwoFactorStatus.forced: 3,
};
