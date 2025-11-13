part of '../gsd_restapi.dart';

class RestApiSyncContainer {
  final String containerId;
  final String contentId;
  final bool readOnly;
  final int count;
  final int revision;
  final int startMarker;
  final int endMarker;
  final int nextMarker;
  final bool hasMoreData;
  final List<RestApiSyncDataClass> classes;
  final List<dynamic> excluded;
  final List<dynamic> deleted;

  RestApiSyncContainer({
    required this.containerId,
    this.contentId = "",
    this.readOnly = false,
    this.count = 0,
    required this.revision,
    this.startMarker = 0,
    this.endMarker = 0,
    required this.nextMarker,
    this.hasMoreData = false,
    this.classes = const [],
    this.excluded = const [],
    this.deleted = const [],
  });

  factory RestApiSyncContainer.fromJson(Map<String, dynamic> json) {
    return RestApiSyncContainer(
      containerId: json['containerId'] ?? '',
      contentId: json['contentId'] ?? '',
      readOnly: json['readOnly'] ?? false,
      count: json['count'] ?? 0,
      revision: json['revision'] is String
          ? int.tryParse(json['revision']) ?? 0
          : json['revision'] ?? 0,
      startMarker: json['startMarker'] is String
          ? int.tryParse(json['startMarker']) ?? 0
          : json['startMarker'] ?? 0,
      endMarker: json['endMarker'] is String
          ? int.tryParse(json['endMarker']) ?? 0
          : json['endMarker'] ?? 0,
      nextMarker: json['nextMarker'] is String
          ? int.tryParse(json['nextMarker']) ?? 0
          : json['nextMarker'] ?? 0,
      hasMoreData: json['hasMoreData'] ?? false,
      classes:
          (json['classes'] as List<dynamic>?)
              ?.map(
                (e) => RestApiSyncDataClass.fromJson(e as Map<String, dynamic>),
              )
              .toList() ??
          [],
      excluded: json['excluded'] ?? [],
      deleted: json['deleted'] ?? [],
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'containerId': containerId,
      'contentId': contentId,
      'readOnly': readOnly,
      'count': count,
      'revision': revision,
      'startMarker': startMarker,
      'endMarker': endMarker,
      'nextMarker': nextMarker,
      'hasMoreData': hasMoreData,
      'classes': classes.map((e) => e.toJson()).toList(),
      'excluded': excluded,
      'deleted': deleted,
    };
  }
}
