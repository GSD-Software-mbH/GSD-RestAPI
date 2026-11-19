// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'gsd_object_lock.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

GsdObjectLock _$GsdObjectLockFromJson(Map<String, dynamic> json) =>
    $checkedCreate('GsdObjectLock', json, ($checkedConvert) {
      final val = GsdObjectLock(
        isLocked: $checkedConvert('isLocked', (v) => v as bool),
        messages: $checkedConvert(
          'messages',
          (v) => v == null ? const [] : GsdObjectLock._messagesFromJson(v),
        ),
      );
      return val;
    });
