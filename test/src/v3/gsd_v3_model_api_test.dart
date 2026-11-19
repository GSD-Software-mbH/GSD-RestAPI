@TestOn('vm')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
// V3-Endpunkt-Tests für `api.v3.model` und `/v3/`-Pfade.
//
// Die Tests laufen gegen den lokalen Mock-Server und prüfen den
// Client-Vertrag (Pfad, Verb, Body, Rückgabe, kein v1/multi).

import 'package:test/test.dart';

import 'v3_test_support.dart';

void main() {
  late V3TestHarness harness;

  setUp(() async {
    harness = await V3TestHarness.start();
  });

  tearDown(() => harness.close());

  test(
    'model.structure übernimmt den realen DOCUframe-App-Request unverändert',
    () async {
      final data = [
        {'className': 'Object', 'members': <Object?>[]},
      ];
      harness.enqueueData('POST', '/dfapp/v3/model/structure', data);

      final structure = await harness.api.executeWithPriority(
        () => harness.api.v3.model.structure([
          const GsdStructureRequest(
            className: 'Object',
            skipDerivedClasses: false,
            skipMembers: false,
            skipBaseMembers: true,
            skipIndices: false,
            skipValueMapping: false,
          ),
        ]),
        GsdRequestPriority.low,
      );

      expect(structure, data);
      harness.expectSingleRequest(
        method: 'POST',
        path: '/dfapp/v3/model/structure',
        body: loadV3Fixture('model_structure_request.json'),
      );
    },
  );
}
