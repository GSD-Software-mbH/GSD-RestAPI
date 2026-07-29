import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/raw/api_types.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/batch/multi_request_eligibility.dart';

void main() {
  bool allows(ApiVersion version, String path) =>
      MultiRequestEligibility.allows(
        target: ApiRequestTarget.versioned(version: version, path: path),
      );

  test('all V2 routes are centrally excluded from v1/multi', () {
    expect(allows(ApiVersion.v2, '/model/structure'), isFalse);
    expect(allows(ApiVersion.v2, '/view/load'), isFalse);
    expect(allows(ApiVersion.v2, '/objectdata/byid'), isFalse);
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
      expect(allows(ApiVersion.v1, path), isFalse, reason: path);
    }
  });

  test('ordinary and eligible service V1 endpoints remain multi-capable', () {
    for (final path in <String>[
      '/objects/Document',
      '/license/release',
      '/versioninfo',
    ]) {
      expect(allows(ApiVersion.v1, path), isTrue, reason: path);
    }
  });

  test('absolute targets are never multi-request eligible', () {
    expect(
      MultiRequestEligibility.allows(
        target: ApiRequestTarget.absolute(
          Uri.parse('https://status.example/_CheckService'),
        ),
      ),
      isFalse,
    );
  });
}
