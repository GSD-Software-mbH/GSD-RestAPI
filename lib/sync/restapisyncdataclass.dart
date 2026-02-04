part of '../gsd_restapi.dart';

class RestApiSyncDataClass {
  final String className;
  final int count;
  final List<String> header;
  final List<List<dynamic>> data;

  RestApiSyncDataClass({
    required this.className,
    required this.count,
    required this.header,
    required this.data,
  });

  factory RestApiSyncDataClass.fromJson(Map<String, dynamic> json) {
    return RestApiSyncDataClass(
      className: json['className'] ?? '',
      count: json['count'] ?? 0,
      header: List<String>.from(json['header'] ?? []),
      data:
          (json['data'] as List<dynamic>?)
              ?.map((e) => List<dynamic>.from(e as List))
              .toList() ??
          [],
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'className': className,
      'count': count,
      'header': header,
      'data': data,
    };
  }
}
