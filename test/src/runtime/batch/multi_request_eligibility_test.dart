import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/batch/multi_request_eligibility.dart';
import 'package:test/test.dart';

void main() {
  bool allows(GsdApiVersion version, String path) =>
      MultiRequestEligibility.allows(
        target: ApiRequestTarget.versioned(version: version, path: path),
      );

  test('all V2 routes are centrally excluded from v1/multi', () {
    expect(allows(GsdApiVersion.v2, '/model/structure'), isFalse);
    expect(allows(GsdApiVersion.v2, '/view/load'), isFalse);
    expect(allows(GsdApiVersion.v2, '/objectdata/byid'), isFalse);
  });

  test('all V3 routes are centrally excluded from v1/multi', () {
    expect(allows(GsdApiVersion.v3, '/model/structure'), isFalse);
    expect(allows(GsdApiVersion.v3, '/view/load'), isFalse);
    expect(allows(GsdApiVersion.v3, '/objectdata/byid'), isFalse);
  });

  test('V3 is excluded even on paths that are multi-capable under V1', () {
    // Trifft die Versionsregel und nicht bloß eine Pfad-Denylist: dieselben
    // Pfade sind unter V1 erlaubt und unter V3 ausgeschlossen.
    for (final path in <String>[
      '/objects/Document',
      '/license/release',
      '/versioninfo',
    ]) {
      expect(allows(GsdApiVersion.v1, path), isTrue, reason: 'v1 $path');
      expect(allows(GsdApiVersion.v3, path), isFalse, reason: 'v3 $path');
    }
  });

  test('version gate is an allowlist: only V1 may enter v1/multi', () {
    // Regressionsschutz für die Umstellung von Denylist (== v2) auf
    // Allowlist (!= v1): jede bestehende und künftige Version außer V1 ist
    // ausgeschlossen, V1 bleibt unverändert erlaubt.
    for (final version in GsdApiVersion.values) {
      expect(
        allows(version, '/objects/Document'),
        version == GsdApiVersion.v1,
        reason: version.name,
      );
    }
  });

  test('unversioned session and service checks are direct', () {
    expect(
      MultiRequestEligibility.allows(
        target: const ApiRequestTarget.unversioned('/_CheckSession'),
      ),
      isFalse,
    );
    expect(
      MultiRequestEligibility.allows(
        target: const ApiRequestTarget.unversioned('/_CheckService'),
      ),
      isFalse,
    );
  });

  test('authentication, sync, and binary or upload paths are direct', () {
    for (final path in <String>[
      '/logout',
      '/xSync/app/class',
      '/uploadFile',
      '/uploadFile/id-1',
      '/file/document-1',
      '/preview/pdf/keep-ratio/document-1/0',
    ]) {
      expect(allows(GsdApiVersion.v1, path), isFalse, reason: path);
    }
  });

  test('ordinary and eligible service V1 endpoints remain multi-capable', () {
    for (final path in <String>[
      '/objects/Document',
      '/license/release',
      '/versioninfo',
    ]) {
      expect(allows(GsdApiVersion.v1, path), isTrue, reason: path);
    }
  });
}
