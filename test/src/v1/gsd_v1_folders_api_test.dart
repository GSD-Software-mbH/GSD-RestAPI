@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';
import 'v1_test_support.dart';

void main() {
  late V1TestHarness native;

  setUp(() async {
    native = await V1TestHarness.start();

    ScriptedResponse success(RecordedRequest _) => ScriptedResponse(
      jsonEncode(TestServer.v1Envelope(data: <String, dynamic>{'ok': true})),
    );
    native.server.fallback = success;
  });

  tearDown(() async {
    await native.close();
  });

  final cases = <(String, Future<void> Function(GsdV1FoldersApi))>[
    (
      'getFolderByType',
      (api) async {
        await api.getFolderByType(
          'Inbox',
          reverseOrder: true,
          page: 2,
          perPage: 25,
          query: 'urgent',
        );
      },
    ),
    (
      'getFolderByOid',
      (api) async {
        await api.getFolderByOid(
          'folder-1',
          reverseOrder: true,
          page: 2,
          perPage: 25,
          query: 'urgent',
        );
      },
    ),
    (
      'getFolderByPath',
      (api) async {
        await api.getFolderByPath(
          r'\Projekte\2026',
          reverseOrder: true,
          page: 2,
          perPage: 25,
          query: 'urgent',
        );
      },
    ),
    (
      'postFolders',
      (api) async {
        await api.postFolders(
          'Child',
          'parent-1',
          parentFolderSourceType: GsdDocuframeFolderType.oid,
        );
      },
    ),
    (
      'deleteFolders',
      (api) async {
        await api.deleteFolders('/Temp', notEmpty: true);
      },
    ),
    (
      'patchFoldersRename',
      (api) async {
        await api.patchFoldersRename('folder-1', 'Renamed');
      },
    ),
    (
      'patchFoldersAdd',
      (api) async {
        await api.patchFoldersAdd(
          GsdDocuframeFolderType.path,
          r'\Inbox A',
          <String>['doc-1', 'doc-2'],
          className: 'Dokument',
        );
      },
    ),
    (
      'patchFoldersRemoveDocuments',
      (api) async {
        await api.patchFoldersRemoveDocuments(
          GsdDocuframeFolderType.oid,
          'folder-1',
          <String>['doc-1'],
          className: 'Dokument',
          moveToTrashBin: false,
          deep: <String>['nested'],
        );
      },
    ),
    (
      'patchFoldersCopyDocuments',
      (api) async {
        await api.patchFoldersCopyDocuments(
          GsdDocuframeFolderType.path,
          '/Target',
          <String>['doc-1'],
          sourceFolderSourceType: GsdDocuframeFolderType.oid,
          sourceFolderId: '',
          cut: false,
        );
      },
    ),
  ];

  for (final (name, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callNative(native.api.v1.folders);

      expect(native.server.requests, hasLength(1));
      native.expectLegacyWire('folders.$name', native.server.requests.single);
    });
  }

  test('Default-Paginierung stammt aus dem Runtime-Config-Snapshot', () async {
    await native.api.v1.folders.getFolderByType('Inbox');

    expect(native.server.requests.single.query, const <String, String>{
      'perPage': '50',
    });
  });

  test('Runtime-Settings steuern Paginierung und Folder-Encoding', () async {
    native.api.updateRuntimeSettings(
      perPageCount: 25,
      useFolderPathEncoding: true,
    );

    await native.api.v1.folders.getFolderByPath(r'\Projekte\2026');

    expect(native.server.requests.single.query, const <String, String>{
      'perPage': '25',
    });
    expect(native.server.requests.single.path, contains('%255C'));
  });

  test('identische schreibende Aufrufe werden nicht dedupliziert', () async {
    await Future.wait(<Future<Object?>>[
      native.api.v1.folders.patchFoldersRename('folder-1', 'Renamed'),
      native.api.v1.folders.patchFoldersRename('folder-1', 'Renamed'),
    ]);

    expect(native.server.requests, hasLength(2));
  });
}
