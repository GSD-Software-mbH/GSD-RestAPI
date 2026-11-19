import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/deduplication_policy.dart';
import 'package:meta/meta.dart';

/// Führt die gleichförmigen V1-Aufrufe einer Gruppe aus: mit Session,
/// `data` als `Object?`, GET dedupliziert.
@internal
class V1Requester {
  /// Ein Requester für eine V1-Gruppe; die Operation-IDs heißen
  /// `v1.<group>.<operation>`.
  const V1Requester(this._runtime, this._group);

  final ApiRuntime _runtime;
  final String _group;

  /// Eine Instanz für alle Aufrufe: Der Dedup-Schlüssel vergleicht die
  /// Policy per Identität.
  static const DataResponsePolicy<Object?> _responsePolicy =
      DataResponsePolicy<Object?>();

  /// Sendet den Aufruf und liefert `data` der Antwort.
  Future<Object?> execute({
    required GsdHttpMethod method,
    required String path,
    required String operation,
    Map<String, String>? queryParameters,
    String? body,
  }) {
    return _runtime.execute(
      ApiRequest<Object?>(
        method: method,
        version: GsdApiVersion.v1,
        path: path,
        queryParameters: queryParameters,
        body: body,
        authentication: AuthenticationPolicy.session,
        deduplication: method == GsdHttpMethod.get
            ? DeduplicationPolicy.enabled
            : DeduplicationPolicy.disabled,
        responsePolicy: _responsePolicy,
        operationId: 'v1.$_group.$operation',
      ),
    );
  }
}
