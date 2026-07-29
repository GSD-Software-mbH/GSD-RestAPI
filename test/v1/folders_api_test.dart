// ignore_for_file: deprecated_member_use_from_same_package

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

import '../legacy/legacy_test_server.dart';
import 'v1_test_support.dart';

void main() {
  late LegacyTestServer legacyServer;
  late RestApiDOCUframeManager legacy;
  late V1TestHarness native;

  setUp(() async {
    HttpOverrides.global = null;
    legacyServer = LegacyTestServer();
    await legacyServer.start();
    legacy = RestApiDOCUframeManager(
      config: buildLegacyConfig(
        legacyServer,
        sessionId: V1TestHarness.sessionId,
      ),
    );
    native = await V1TestHarness.start();

    ScriptedResponse success(RecordedRequest _) => ScriptedResponse(
      jsonEncode(v1Envelope(data: <String, dynamic>{'ok': true})),
    );
    legacyServer.fallback = success;
    native.server.fallback = success;
  });

  tearDown(() async {
    legacy.dispose();
    await legacyServer.close();
    await native.close();
  });

  final List<
    (
      String,
      Future<void> Function(RestApiDOCUframeManager),
      Future<void> Function(V1FoldersApi),
    )
  >
  cases =
      <
        (
          String,
          Future<void> Function(RestApiDOCUframeManager),
          Future<void> Function(V1FoldersApi),
        )
      >[
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
              parentFolderSourceType: RestApiDOCUframeFolderType.oid,
            );
          },
          (api) async {
            await api.postFolders(
              'Child',
              'parent-1',
              parentFolderSourceType: RestApiDOCUframeFolderType.oid,
            );
          },
        ),
        (
          'deleteFolders',
          (api) async {
            await api.deleteFolders('/Temp', notEmpty: true);
          },
          (api) async {
            await api.deleteFolders('/Temp', notEmpty: true);
          },
        ),
        (
          'patchFoldersRename',
          (api) async {
            await api.patchFoldersRename('folder-1', 'Renamed');
          },
          (api) async {
            await api.patchFoldersRename('folder-1', 'Renamed');
          },
        ),
        (
          'patchFoldersAdd',
          (api) async {
            await api.patchFoldersAdd(
              RestApiDOCUframeFolderType.path,
              r'\Inbox A',
              <String>['doc-1', 'doc-2'],
              className: 'Dokument',
            );
          },
          (api) async {
            await api.patchFoldersAdd(
              RestApiDOCUframeFolderType.path,
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
              RestApiDOCUframeFolderType.oid,
              'folder-1',
              <String>['doc-1'],
              className: 'Dokument',
              moveToTrashBin: false,
              deep: <String>['nested'],
            );
          },
          (api) async {
            await api.patchFoldersRemoveDocuments(
              RestApiDOCUframeFolderType.oid,
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
              RestApiDOCUframeFolderType.path,
              '/Target',
              <String>['doc-1'],
              sourceFolderSourceType: RestApiDOCUframeFolderType.oid,
              sourceFolderId: '',
              cut: false,
            );
          },
          (api) async {
            await api.patchFoldersCopyDocuments(
              RestApiDOCUframeFolderType.path,
              '/Target',
              <String>['doc-1'],
              sourceFolderSourceType: RestApiDOCUframeFolderType.oid,
              sourceFolderId: '',
              cut: false,
            );
          },
        ),
      ];

  for (final (name, callLegacy, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callLegacy(legacy);
      await callNative(native.api.v1.folders);

      expect(legacyServer.requests, hasLength(1));
      expect(native.server.requests, hasLength(1));
      final RecordedRequest legacyRequest = legacyServer.requests.single;
      final RecordedRequest nativeRequest = native.server.requests.single;
      expect(nativeRequest.method, legacyRequest.method);
      expect(nativeRequest.path, legacyRequest.path);
      expect(nativeRequest.query, legacyRequest.query);
      expect(nativeRequest.body, legacyRequest.body);
      expect(
        nativeRequest.header('sessionid'),
        legacyRequest.header('sessionid'),
      );
      expect(nativeRequest.header('appkey'), legacyRequest.header('appkey'));
    });
  }

  test('Default-Paginierung stammt aus dem Runtime-Config-Snapshot', () async {
    await native.api.v1.folders.getFolderByType('Inbox');

    expect(native.server.requests.single.query, const <String, String>{
      'perPage': '50',
    });
  });

  test('Management-Settings steuern Paginierung und Folder-Encoding', () async {
    native.api.management.updateRuntimeSettings(
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
    await Future.wait(<Future<RestApiResponse>>[
      native.api.v1.folders.patchFoldersRename('folder-1', 'Renamed'),
      native.api.v1.folders.patchFoldersRename('folder-1', 'Renamed'),
    ]);

    expect(native.server.requests, hasLength(2));
  });
}
