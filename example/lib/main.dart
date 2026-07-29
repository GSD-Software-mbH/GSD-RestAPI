// ignore_for_file: deprecated_member_use

import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:gsd_restapi/docuframe_api.dart' show DOCUframeApi;
import 'package:gsd_restapi/gsd_restapi.dart';

enum ApiArchitecture { legacy, modern }

enum V2ExampleEndpoint {
  modelStructure('model.structure', true),
  versionInfo('system.versionInfo', false),
  appConfig('system.appConfig', false),
  appTheme('system.appTheme', false),
  viewLoad('view.load', true),
  viewAction('view.action', true),
  objectDataById('objectData.getById', true),
  objectDataByQuery('objectData.getByQuery', true),
  objectDataByParentObject('objectData.getByParentObject', true);

  const V2ExampleEndpoint(this.label, this.acceptsBody);

  final String label;
  final bool acceptsBody;

  Object? get examplePayload => switch (this) {
    V2ExampleEndpoint.modelStructure => <Object>[
      <String, Object>{
        'className': 'Object',
        'skipDerivedClasses': false,
        'skipMembers': false,
        'skipBaseMembers': true,
        'skipIndices': false,
        'skipValueMapping': false,
      },
    ],
    V2ExampleEndpoint.viewLoad => <Object>[
      <String, Object>{
        'type': '1',
        'viewName': 'edit',
        'className': 'Dokument',
        'context': 'mobile',
      },
    ],
    V2ExampleEndpoint.viewAction => <String, Object>{
      'action': <String, Object>{'oid': 'ACTION-OID'},
      'data': <String, Object>{
        'objectOid': 'OBJECT-OID',
        'values': <String, Object>{'Name': 'Test'},
      },
    },
    V2ExampleEndpoint.objectDataById => <Object>[
      <String, Object>{
        'classId': 100,
        'type': '',
        'context': 'edit',
        'ids': <int>[200, 201],
      },
    ],
    V2ExampleEndpoint.objectDataByQuery => <Object>[
      <String, Object>{
        'className': 'Dokument',
        'type': '0',
        'query': 'Name=Test',
      },
    ],
    V2ExampleEndpoint.objectDataByParentObject => <Object>[
      <String, Object>{
        'parentOID': 'PARENT-OID',
        'member': 'Dokumente',
        'context': 'edit',
        'idList': true,
      },
    ],
    V2ExampleEndpoint.versionInfo ||
    V2ExampleEndpoint.appConfig ||
    V2ExampleEndpoint.appTheme => null,
  };
}

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'GSD RestAPI Example',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: const RestApiExample(),
    );
  }
}

class RestApiExample extends StatefulWidget {
  const RestApiExample({super.key});

  @override
  State<RestApiExample> createState() => _RestApiExampleState();
}

class _RestApiExampleState extends State<RestApiExample> {
  RestApiDOCUframeManager? _legacyApiManager;
  DOCUframeApi? _modernApi;
  ApiArchitecture _architecture = ApiArchitecture.legacy;
  int _apiGeneration = 0;
  String _status = 'Not connected';
  String _sessionId = 'None';
  bool _isLoggedIn = false;
  final _accountForm = GlobalKey<FormState>();
  final List<String> _logs = [];
  final TextEditingController _urlController = TextEditingController(
    text: 'https://demo.docuframe.com',
  );
  final TextEditingController _aliasController = TextEditingController(
    text: 'gsd',
  );
  final TextEditingController _usernameController = TextEditingController(
    text: 'demo',
  );
  final TextEditingController _passwordController = TextEditingController(
    text: '',
  );
  final TextEditingController _appnameController = TextEditingController(
    text: 'gsd-restapi',
  );
  final TextEditingController _bufferFlushDelayController =
      TextEditingController(text: '100');
  final TextEditingController _v2BodyController = TextEditingController(
    text: '{}',
  );
  final TextEditingController _v2FileOidController = TextEditingController();
  final TextEditingController _v2FilePageController = TextEditingController();
  final TextEditingController _v2FileAttachItemController =
      TextEditingController();
  final TextEditingController _v2FileZipItemController =
      TextEditingController();
  final TextEditingController _v2FileMaxSizeController =
      TextEditingController();

  /// `null` bedeutet: `usePdf` wird gar nicht gesendet.
  bool? _v2FileUsePdf;
  String _v2Response = 'Noch keine V2-Anfrage ausgeführt.';
  String _v2FileResult = 'Noch kein Datei-Download ausgeführt.';
  Uint8List? _v2FilePreviewBytes;
  bool _allowSslError = false;
  bool _allowMultiRequest = false;
  bool _isConfigured = false;
  bool _isChecking = false;

  bool get _usesModernApi => _architecture == ApiArchitecture.modern;

  String get _architectureLabel => _usesModernApi ? 'Neue API' : 'Legacy';

  @override
  void dispose() {
    _legacyApiManager?.dispose();
    final DOCUframeApi? modernApi = _modernApi;
    if (modernApi != null) {
      unawaited(modernApi.dispose());
    }
    _urlController.dispose();
    _aliasController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    _appnameController.dispose();
    _bufferFlushDelayController.dispose();
    _v2BodyController.dispose();
    _v2FileOidController.dispose();
    _v2FilePageController.dispose();
    _v2FileAttachItemController.dispose();
    _v2FileZipItemController.dispose();
    _v2FileMaxSizeController.dispose();
    super.dispose();
  }

  RestApiDOCUframeCallbacks _createCallbacks(String source, int generation) {
    return RestApiDOCUframeCallbacks(
      onSessionIdChanged: (sessionId) async {
        _setStateForGeneration(generation, () {
          _sessionId = sessionId;
          _addLog('Session ID changed: $_sessionId');
        });
      },
      onUserAndPassWrong: (exception) async {
        _setStateForGeneration(generation, () {
          _addLog('Authentication failed: ${exception.message}');
        });
      },
      onLicenseWrong: (exception) async {
        _setStateForGeneration(generation, () {
          _addLog('License error detected: ${exception.message}');
        });
      },
      onLogMessage: (message) async {
        _setStateForGeneration(generation, () {
          _addLog('$source: $message');
        });
      },
      onHttpMetricRecorded: (RestApiHttpMetric metric) async {
        _setStateForGeneration(generation, () {
          _addLog(
            "API Call: ${metric.path} - ${metric.duration?.inMilliseconds}ms",
          );
        });
      },
    );
  }

  void _setStateForGeneration(int generation, VoidCallback update) {
    if (!mounted || generation != _apiGeneration) {
      return;
    }
    setState(update);
  }

  void _addLog(String message) {
    _logs.add('${DateTime.now().toLocal()}: $message');
    if (_logs.length > 20) {
      _logs.removeAt(0);
    }
  }

  RestApiDOCUframeConfig _buildConfiguration() {
    return RestApiDOCUframeConfig(
      appKey: '123',
      userName: _usernameController.text,
      appNames: <String>[_appnameController.text],
      serverUrl: _urlController.text,
      alias: _aliasController.text,
      allowSslError: _allowSslError,
      device: RestApiDevice('gsd_utilities_example_app'),
      multiRequest: _allowMultiRequest,
      bufferFlushDelayMs: int.parse(_bufferFlushDelayController.text),
    );
  }

  Future<void> _releaseApis() async {
    _apiGeneration++;
    _legacyApiManager?.dispose();
    _legacyApiManager = null;

    final DOCUframeApi? modernApi = _modernApi;
    _modernApi = null;
    if (modernApi != null) {
      await modernApi.dispose();
    }
  }

  Future<void> _switchArchitecture(Set<ApiArchitecture> selection) async {
    if (selection.isEmpty || selection.first == _architecture || _isChecking) {
      return;
    }

    await _releaseApis();
    if (!mounted) {
      return;
    }

    setState(() {
      _architecture = selection.first;
      _isConfigured = false;
      _isLoggedIn = false;
      _sessionId = 'None';
      _status = 'Not connected';
      _v2Response = 'Noch keine V2-Anfrage ausgeführt.';
      _addLog('Switched to $_architectureLabel architecture');
    });
  }

  Future<void> _checkService() async {
    final int generation = _apiGeneration;
    final bool usesModernApi = _usesModernApi;
    try {
      _setStateForGeneration(generation, () {
        _status = 'Checking service...';
      });

      final RestApiCheckServiceResponse response = usesModernApi
          ? await _modernApi!.v1.service.checkService()
          : await _legacyApiManager!.checkService();

      _setStateForGeneration(generation, () {
        _status = response.isOk ? 'Service available' : 'Service unavailable';
        _addLog('Service check: ${response.isOk ? 'OK' : 'Failed'}');
      });
    } catch (e) {
      _setStateForGeneration(generation, () {
        _status = 'Service check failed';
        _addLog('Service check error: $e');
      });
    }
  }

  Future<void> _login() async {
    final int generation = _apiGeneration;
    final bool usesModernApi = _usesModernApi;
    try {
      _setStateForGeneration(generation, () {
        _status = 'Logging in...';
      });

      final String md5Password = _passwordController.text.toMd5Hash();
      final RestApiLoginResponse loginResponse = usesModernApi
          ? await _modernApi!.v1.authentication.login(md5Password)
          : await _legacyApiManager!.login(md5Password);

      _setStateForGeneration(generation, () {
        _isLoggedIn = loginResponse.isOk;
        _status = _isLoggedIn ? 'Logged in successfully' : 'Login failed';
        _sessionId = usesModernApi
            ? _modernApi!.sessionId
            : _legacyApiManager!.config.sessionId;
        _addLog('Login attempt: ${_isLoggedIn ? 'Success' : 'Failed'}');
      });
    } catch (e) {
      _setStateForGeneration(generation, () {
        _status = 'Login error';
        _isLoggedIn = false;
        _addLog('Login error: $e');
      });
    }
  }

  Future<void> _getDocumentCount() async {
    final int generation = _apiGeneration;
    final bool usesModernApi = _usesModernApi;
    try {
      _setStateForGeneration(generation, () {
        _status = 'Fetching document count...';
      });

      final int count;
      if (usesModernApi) {
        final RestApiResponse response = await _modernApi!.v1.objects
            .getObjects('Dokument');
        count = _documentCount(
          jsonDecode(response.httpResponse.body) as Map<String, dynamic>,
        );
      } else {
        final RestApiResponse response = await _legacyApiManager!.getObjects(
          'Dokument',
        );
        count = _documentCount(
          jsonDecode(response.httpResponse.body) as Map<String, dynamic>,
        );
      }

      _setStateForGeneration(generation, () {
        _status = 'Document count fetched: $count';
        _addLog('Document count: $count');
      });
    } catch (e) {
      _setStateForGeneration(generation, () {
        _status = 'Error fetching document count';
        _addLog('Document count error: $e');
      });
    }
  }

  Future<void> _createNote() async {
    final int generation = _apiGeneration;
    final bool usesModernApi = _usesModernApi;
    try {
      _setStateForGeneration(generation, () {
        _status = 'Creating note...';
      });

      final String body = jsonEncode({
        'Text': 'Dies ist eine automatisch erstellte Notiz.',
        'Name': 'Testnotiz ${DateTime.now().toIso8601String()}',
        'Beschreibung': 'Notiz erstellt via GSD RestAPI Flutter Beispiel',
        '~StoreTime': DateTime.now().toISOFormatString(),
      });

      if (usesModernApi) {
        await _modernApi!.v1.objects.postObject('Notiz', body, storeMode: 10);
      } else {
        await _legacyApiManager!.postObject('Notiz', body, storeMode: 10);
      }

      _setStateForGeneration(generation, () {
        _status = 'Note created successfully';
        _addLog('Note created successfully');
      });
    } catch (e) {
      _setStateForGeneration(generation, () {
        _status = 'Error creating note';
        _addLog('Note creation error: $e');
      });
    }
  }

  Future<void> _testMultiRequest() async {
    final int generation = _apiGeneration;
    final bool usesModernApi = _usesModernApi;
    try {
      _setStateForGeneration(generation, () {
        _status = 'Testing MultiRequest with 10 distinct pages...';
      });

      final List<int> counts;
      if (usesModernApi) {
        final List<RestApiResponse> responses = await Future.wait(
          List<Future<RestApiResponse>>.generate(
            10,
            (index) =>
                _modernApi!.v1.objects.getObjects('Dokument', page: index),
          ),
        );
        counts = responses
            .map(
              (response) => _documentCount(
                jsonDecode(response.httpResponse.body) as Map<String, dynamic>,
              ),
            )
            .toList(growable: false);
      } else {
        final List<RestApiResponse> responses = await Future.wait(
          List<Future<RestApiResponse>>.generate(
            10,
            (index) => _legacyApiManager!.getObjects('Dokument', page: index),
          ),
        );
        counts = responses
            .map(
              (response) => _documentCount(
                jsonDecode(response.httpResponse.body) as Map<String, dynamic>,
              ),
            )
            .toList(growable: false);
      }

      _setStateForGeneration(generation, () {
        _addLog('MultiRequest test completed for pages 0-9');
        for (var index = 0; index < counts.length; index++) {
          _addLog('Page $index: Document count: ${counts[index]}');
        }
        _status = 'MultiRequest test completed successfully';
      });
    } catch (e) {
      _setStateForGeneration(generation, () {
        _status = 'MultiRequest test failed';
        _addLog('MultiRequest test error: $e');
      });
    }
  }

  Future<void> _checkSession() async {
    final int generation = _apiGeneration;
    final bool usesModernApi = _usesModernApi;
    try {
      _setStateForGeneration(generation, () {
        _status = 'Checking session...';
      });

      final RestApiResponse sessionResponse = usesModernApi
          ? await _modernApi!.v1.authentication.checkSession()
          : await _legacyApiManager!.checkSession();

      _setStateForGeneration(generation, () {
        _status = sessionResponse.isOk ? 'Session valid' : 'Session invalid';
        _addLog('Session check: ${sessionResponse.isOk ? 'Valid' : 'Invalid'}');
      });
    } catch (e) {
      _setStateForGeneration(generation, () {
        _status = 'Session check failed';
        _addLog('Session check error: $e');
      });
    }
  }

  Future<void> _logout() async {
    final int generation = _apiGeneration;
    final bool usesModernApi = _usesModernApi;
    try {
      _setStateForGeneration(generation, () {
        _status = 'Logging out...';
      });

      if (usesModernApi) {
        await _modernApi!.v1.authentication.logout();
      } else {
        await _legacyApiManager!.logout();
      }

      _setStateForGeneration(generation, () {
        _isLoggedIn = false;
        _sessionId = 'None';
        _status = 'Logged out';
        _addLog('Logged out successfully');
      });
    } catch (e) {
      _setStateForGeneration(generation, () {
        _status = 'Logout error';
        _addLog('Logout error: $e');
      });
    }
  }

  Future<void> _executeV2Endpoint(V2ExampleEndpoint endpoint) async {
    final int generation = _apiGeneration;

    try {
      _setStateForGeneration(generation, () {
        _status = 'Calling v2.${endpoint.label}...';
      });

      String? body;
      if (endpoint.acceptsBody) {
        final String candidate = _v2BodyController.text.trim();
        if (candidate.isNotEmpty) {
          jsonDecode(candidate);
          body = candidate;
        }
      }

      final Future<RestApiResponse> request = switch (endpoint) {
        V2ExampleEndpoint.modelStructure => _modernApi!.v2.model.structure(
          body: body,
        ),
        V2ExampleEndpoint.versionInfo => _modernApi!.v2.system.versionInfo(),
        V2ExampleEndpoint.appConfig => _modernApi!.v2.system.appConfig(),
        V2ExampleEndpoint.appTheme => _modernApi!.v2.system.appTheme(),
        V2ExampleEndpoint.viewLoad => _modernApi!.v2.view.load(body: body),
        V2ExampleEndpoint.viewAction => _modernApi!.v2.view.action(body: body),
        V2ExampleEndpoint.objectDataById => _modernApi!.v2.objectData.getById(
          body: body,
        ),
        V2ExampleEndpoint.objectDataByQuery =>
          _modernApi!.v2.objectData.getByQuery(body: body),
        V2ExampleEndpoint.objectDataByParentObject =>
          _modernApi!.v2.objectData.getByParentObject(body: body),
      };
      final RestApiResponse response = await request;
      final String formattedResponse = _formatJson(response.httpResponse.body);

      _setStateForGeneration(generation, () {
        _status = 'v2.${endpoint.label} completed';
        _v2Response = formattedResponse;
        _addLog(
          'V2 ${endpoint.label}: HTTP ${response.httpResponse.statusCode}, '
          'internal status ${response.internalStatus}',
        );
      });
    } on FormatException catch (error) {
      _setStateForGeneration(generation, () {
        _status = 'Invalid V2 JSON body';
        _addLog('V2 ${endpoint.label}: invalid JSON body ($error)');
      });
    } catch (error) {
      _setStateForGeneration(generation, () {
        _status = 'V2 request failed';
        _addLog('V2 ${endpoint.label} error: $error');
      });
    }
  }

  /// Liest ein optionales Zahlenfeld: leer bedeutet "Parameter nicht senden".
  ///
  /// Wirft [FormatException], damit ein Tippfehler nicht still als `null`
  /// durchrutscht und dadurch einen anderen Request sendet als gedacht.
  int? _optionalIntParameter(String label, TextEditingController controller) {
    final String raw = controller.text.trim();
    if (raw.isEmpty) {
      return null;
    }
    final int? value = int.tryParse(raw);
    if (value == null) {
      throw FormatException('$label ist keine ganze Zahl: "$raw"');
    }
    return value;
  }

  /// Zeigt die URL, die der Aufruf erzeugt - damit im Log sichtbar ist, dass
  /// nicht gesetzte Parameter wirklich fehlen.
  String _describeV2FileRequest(String oid, Map<String, String> query) {
    if (query.isEmpty) {
      return 'v2/file/$oid';
    }
    final String queryString = query.entries
        .map((entry) => '${entry.key}=${entry.value}')
        .join('&');
    return 'v2/file/$oid?$queryString';
  }

  Future<void> _executeV2FileGet() async {
    final int generation = _apiGeneration;
    final String oid = _v2FileOidController.text.trim();

    if (oid.isEmpty) {
      setState(() {
        _status = 'Datei-OID fehlt';
        _addLog('V2 file.get: keine OID angegeben');
      });
      return;
    }

    try {
      final int? page = _optionalIntParameter('page', _v2FilePageController);
      final int? attachItem = _optionalIntParameter(
        'attachItem',
        _v2FileAttachItemController,
      );
      final int? zipItem = _optionalIntParameter(
        'zipItem',
        _v2FileZipItemController,
      );
      final int? maxSize = _optionalIntParameter(
        'maxSize',
        _v2FileMaxSizeController,
      );
      final bool? usePdf = _v2FileUsePdf;

      final String description = _describeV2FileRequest(oid, <String, String>{
        if (page != null) 'page': '$page',
        if (usePdf != null) 'usePdf': '$usePdf',
        if (attachItem != null) 'attachItem': '$attachItem',
        if (zipItem != null) 'zipItem': '$zipItem',
        if (maxSize != null) 'maxSize': '$maxSize',
      });

      _setStateForGeneration(generation, () {
        _status = 'Calling $description...';
        _v2FilePreviewBytes = null;
        _addLog('V2 file.get: GET $description');
      });

      final RestApiFileResponse response = await _modernApi!.v2.file.get(
        oid,
        page: page,
        usePdf: usePdf,
        attachItem: attachItem,
        zipItem: zipItem,
        maxSize: maxSize,
      );

      final Uint8List bytes = response.httpResponse.bodyBytes;
      final String contentType =
          response.httpResponse.headers['content-type'] ?? 'unbekannt';
      final bool isImage = contentType.startsWith('image/');

      _setStateForGeneration(generation, () {
        _status = 'file.get completed';
        _v2FilePreviewBytes = isImage ? bytes : null;
        _v2FileResult =
            'GET $description\n'
            'HTTP ${response.httpResponse.statusCode} (isOk: ${response.isOk})\n'
            'Content-Type: $contentType\n'
            'Bytes: ${bytes.length}';
        _addLog(
          'V2 file.get: HTTP ${response.httpResponse.statusCode}, '
          '${bytes.length} Bytes, $contentType',
        );
      });
    } on FormatException catch (error) {
      _setStateForGeneration(generation, () {
        _status = 'Ungültiger Datei-Parameter';
        _v2FileResult = 'Ungültiger Parameter: ${error.message}';
        _addLog('V2 file.get: ${error.message}');
      });
    } on HttpRequestException catch (error) {
      // RestApiFileResponse wirft bei jedem Status != 200.
      _setStateForGeneration(generation, () {
        _status = 'file.get failed';
        _v2FilePreviewBytes = null;
        _v2FileResult = 'HTTP-Fehler ${error.statusCode}: ${error.message}';
        _addLog('V2 file.get error: HTTP ${error.statusCode}');
      });
    } catch (error) {
      _setStateForGeneration(generation, () {
        _status = 'file.get failed';
        _v2FilePreviewBytes = null;
        _v2FileResult = 'Fehler: $error';
        _addLog('V2 file.get error: $error');
      });
    }
  }

  Widget _buildV2FileIntField({
    required String fieldKey,
    required String label,
    required String helper,
    required TextEditingController controller,
  }) {
    return SizedBox(
      width: 180,
      child: TextField(
        key: ValueKey<String>(fieldKey),
        controller: controller,
        enabled: !_isChecking,
        keyboardType: TextInputType.number,
        inputFormatters: <TextInputFormatter>[
          FilteringTextInputFormatter.digitsOnly,
        ],
        decoration: InputDecoration(
          labelText: label,
          helperText: helper,
          border: const OutlineInputBorder(),
        ),
      ),
    );
  }

  void _loadV2BodyTemplate(V2ExampleEndpoint endpoint) {
    final Object? payload = endpoint.examplePayload;
    if (payload == null) {
      return;
    }

    _v2BodyController.text = const JsonEncoder.withIndent(
      '  ',
    ).convert(payload);
    setState(() {
      _status = 'Vorlage für v2.${endpoint.label} geladen';
    });
  }

  String _formatJson(String source) {
    try {
      return const JsonEncoder.withIndent('  ').convert(jsonDecode(source));
    } on FormatException {
      return source;
    }
  }

  int _documentCount(Map<String, dynamic> envelope) {
    final dynamic data = envelope['data'];
    final dynamic value = data is Map<String, dynamic> ? data['~Count'] : null;
    if (value is int) {
      return value;
    }
    if (value is num) {
      return value.toInt();
    }
    return int.parse(value.toString());
  }

  /// Zeigt einen Fehler-Dialog
  void _showErrorDialog(String title, String message) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text(title),
          content: Text(message),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('OK'),
            ),
          ],
        );
      },
    );
  }

  /// Erstellt genau einen Client für die ausgewählte Architektur.
  Future<void> _configureApi() async {
    setState(() {
      _isChecking = true;
    });

    try {
      await _releaseApis();
      final int generation = _apiGeneration;
      final RestApiDOCUframeConfig configuration = _buildConfiguration();

      if (_usesModernApi) {
        _modernApi = DOCUframeApi(
          configuration: configuration,
          callbacks: _createCallbacks('DOCUframeApi', generation),
        );
      } else {
        _legacyApiManager = RestApiDOCUframeManager(
          config: configuration,
          callbacks: _createCallbacks('RestApiDOCUframeManager', generation),
        );
      }

      if (!mounted) {
        return;
      }
      setState(() {
        _isConfigured = true;
        _status = '$_architectureLabel API configured';
        _addLog('$_architectureLabel API configured');
      });
    } catch (e) {
      if (mounted) {
        _showErrorDialog(
          'Konfigurationsfehler',
          'API konnte nicht erstellt werden:\n$e',
        );
      }
    } finally {
      if (mounted) {
        setState(() {
          _isChecking = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('GSD RestAPI Example'),
        backgroundColor: Colors.blue,
        foregroundColor: Colors.white,
      ),
      body: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Connection Status',
                        style: Theme.of(context).textTheme.headlineSmall,
                      ),
                      const SizedBox(height: 8),
                      Text('Status: $_status'),
                      Text('Session ID: $_sessionId'),
                      Text('Logged in: ${_isLoggedIn ? 'Yes' : 'No'}'),
                      Text('Architecture: $_architectureLabel'),
                      const SizedBox(height: 12),
                      SegmentedButton<ApiArchitecture>(
                        segments: const <ButtonSegment<ApiArchitecture>>[
                          ButtonSegment<ApiArchitecture>(
                            value: ApiArchitecture.legacy,
                            label: Text('Legacy'),
                            icon: Icon(Icons.history),
                          ),
                          ButtonSegment<ApiArchitecture>(
                            value: ApiArchitecture.modern,
                            label: Text('Neue API'),
                            icon: Icon(Icons.auto_awesome),
                          ),
                        ],
                        selected: <ApiArchitecture>{_architecture},
                        onSelectionChanged: _isChecking
                            ? null
                            : _switchArchitecture,
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Form(
                        key: _accountForm,
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              children: [
                                Expanded(
                                  child: Text(
                                    _usesModernApi
                                        ? 'DOCUframeApi konfigurieren'
                                        : 'RestApiDOCUframeManager konfigurieren',
                                    style: Theme.of(
                                      context,
                                    ).textTheme.headlineSmall,
                                  ),
                                ),
                                const SizedBox(width: 8),
                                if (_isConfigured)
                                  Icon(
                                    Icons.check_circle,
                                    color: Colors.green,
                                    size: 20,
                                  ),
                              ],
                            ),
                            const SizedBox(height: 16),

                            // Server URL
                            TextFormField(
                              controller: _urlController,
                              enabled: !_isConfigured,
                              decoration: const InputDecoration(
                                labelText: 'Server URL',
                                border: OutlineInputBorder(),
                                prefixIcon: Icon(Icons.link),
                              ),
                            ),
                            const SizedBox(height: 12),

                            // Alias und Username
                            Row(
                              children: [
                                Expanded(
                                  child: TextFormField(
                                    controller: _aliasController,
                                    enabled: !_isConfigured,
                                    decoration: const InputDecoration(
                                      labelText: 'Alias',
                                      border: OutlineInputBorder(),
                                      prefixIcon: Icon(Icons.alternate_email),
                                    ),
                                  ),
                                ),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: TextFormField(
                                    controller: _usernameController,
                                    enabled: !_isConfigured,
                                    decoration: const InputDecoration(
                                      labelText: 'Username',
                                      border: OutlineInputBorder(),
                                      prefixIcon: Icon(Icons.person),
                                    ),
                                  ),
                                ),
                              ],
                            ),
                            const SizedBox(height: 12),

                            // Passwort
                            TextFormField(
                              controller: _passwordController,
                              enabled: !_isConfigured,
                              obscureText: true,
                              decoration: const InputDecoration(
                                labelText: 'Passwort',
                                border: OutlineInputBorder(),
                                prefixIcon: Icon(Icons.lock),
                              ),
                            ),
                            const SizedBox(height: 12),

                            // Appname
                            TextFormField(
                              controller: _appnameController,
                              enabled: !_isConfigured,
                              decoration: const InputDecoration(
                                labelText: 'Appname',
                                border: OutlineInputBorder(),
                                prefixIcon: Icon(Icons.apps),
                              ),
                            ),
                            const SizedBox(height: 12),

                            // Buffer Flush Delay
                            TextFormField(
                              controller: _bufferFlushDelayController,
                              enabled: !_isConfigured,
                              decoration: const InputDecoration(
                                labelText: 'Buffer Flush Delay (ms)',
                                border: OutlineInputBorder(),
                                prefixIcon: Icon(Icons.timer),
                              ),
                              keyboardType: TextInputType.number,
                              inputFormatters: <TextInputFormatter>[
                                FilteringTextInputFormatter.digitsOnly,
                              ],
                            ),
                            const SizedBox(height: 12),

                            // Allow SSL Error Checkbox
                            CheckboxListTile(
                              title: const Text('SSL-Fehler ignorieren'),
                              subtitle: const Text(
                                'Aktivieren für Entwicklung/Test-Umgebungen',
                              ),
                              value: _allowSslError,
                              enabled: !_isConfigured,
                              onChanged: (value) {
                                setState(() {
                                  _allowSslError = value ?? false;
                                });
                              },
                            ),
                            // Allow Multi-Request Checkbox
                            CheckboxListTile(
                              title: const Text('Multi-Request erlauben'),
                              subtitle: Text(
                                _usesModernApi
                                    ? 'Wird als unveränderlicher Snapshot für '
                                          'native multi-fähige Endpoints übernommen'
                                    : 'Aktivieren um mehrere Anfragen in einer '
                                          'HTTP-Verbindung zu bündeln',
                              ),
                              value: _allowMultiRequest,
                              enabled: !_isConfigured,
                              onChanged: (value) {
                                setState(() {
                                  _allowMultiRequest = value ?? false;
                                });
                              },
                            ),
                            const SizedBox(height: 16),

                            // Konfigurieren Button
                            SizedBox(
                              width: double.infinity,
                              child: OutlinedButton.icon(
                                onPressed: (_isConfigured || _isChecking)
                                    ? null
                                    : () {
                                        if (!_accountForm.currentState!
                                            .validate()) {
                                          return;
                                        }

                                        _configureApi();
                                      },
                                icon: _isChecking
                                    ? const SizedBox(
                                        width: 16,
                                        height: 16,
                                        child: CircularProgressIndicator(
                                          strokeWidth: 2,
                                        ),
                                      )
                                    : const Icon(Icons.settings),
                                label: Text(
                                  _isConfigured
                                      ? 'Konfiguriert'
                                      : _isChecking
                                      ? 'Wird konfiguriert...'
                                      : 'DOCUframe konfigurieren',
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Actions',
                        style: Theme.of(context).textTheme.headlineSmall,
                      ),
                      const SizedBox(height: 8),
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          ElevatedButton(
                            onPressed: _isConfigured ? _checkService : null,
                            child: const Text('Check Service'),
                          ),
                          ElevatedButton(
                            onPressed: _isConfigured && !_isLoggedIn
                                ? _login
                                : null,
                            child: const Text('Login'),
                          ),
                          ElevatedButton(
                            onPressed: _isLoggedIn ? _getDocumentCount : null,
                            child: const Text('Get Document Count'),
                          ),
                          ElevatedButton(
                            onPressed: _isLoggedIn ? _createNote : null,
                            child: const Text('Create Note'),
                          ),
                          ElevatedButton(
                            onPressed: _isLoggedIn && _allowMultiRequest
                                ? _testMultiRequest
                                : null,
                            child: const Text('Test Multi-Request (10 Seiten)'),
                          ),
                          ElevatedButton(
                            onPressed: _isLoggedIn ? _checkSession : null,
                            child: const Text('Check Session'),
                          ),
                          ElevatedButton(
                            onPressed: _isLoggedIn ? _logout : null,
                            child: const Text('Logout'),
                          ),
                        ],
                      ),
                      if (_usesModernApi) ...[
                        const SizedBox(height: 24),
                        const Divider(),
                        const SizedBox(height: 8),
                        Text(
                          'Native V2 Endpoints',
                          style: Theme.of(context).textTheme.headlineSmall,
                        ),
                        const SizedBox(height: 8),
                        const Text(
                          'Diese Aufrufe verwenden direkt api.v2 und niemals '
                          'Legacy, RawApi oder v1/multi.',
                        ),
                        const SizedBox(height: 12),
                        Text(
                          'Bodylose Endpoints',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 8),
                        Wrap(
                          spacing: 8,
                          runSpacing: 8,
                          children: V2ExampleEndpoint.values
                              .where((endpoint) => !endpoint.acceptsBody)
                              .map(
                                (endpoint) => ElevatedButton(
                                  onPressed: _isLoggedIn && !_isChecking
                                      ? () => _executeV2Endpoint(endpoint)
                                      : null,
                                  child: Text('v2.${endpoint.label}'),
                                ),
                              )
                              .toList(growable: false),
                        ),
                        const SizedBox(height: 16),
                        Text(
                          'Endpoints mit JSON Body',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 4),
                        const Text(
                          'Bis die V2-DTOs stabil sind, wird der Request-Inhalt '
                          'dieser POST-Endpunkte als rohes JSON übergeben.',
                        ),
                        const SizedBox(height: 8),
                        const Text(
                          '1. Vorlage laden, 2. Beispielwerte ersetzen, '
                          '3. den passenden Endpoint-Button ausführen.',
                        ),
                        const SizedBox(height: 8),
                        Wrap(
                          spacing: 8,
                          runSpacing: 8,
                          children: V2ExampleEndpoint.values
                              .where((endpoint) => endpoint.acceptsBody)
                              .map(
                                (endpoint) => OutlinedButton.icon(
                                  key: ValueKey<String>(
                                    'v2-template-${endpoint.name}',
                                  ),
                                  onPressed: _isChecking
                                      ? null
                                      : () => _loadV2BodyTemplate(endpoint),
                                  icon: const Icon(Icons.article_outlined),
                                  label: Text('${endpoint.label} Vorlage'),
                                ),
                              )
                              .toList(growable: false),
                        ),
                        const SizedBox(height: 12),
                        TextField(
                          key: const ValueKey<String>('v2-body-field'),
                          controller: _v2BodyController,
                          enabled: !_isChecking,
                          minLines: 3,
                          maxLines: 8,
                          style: const TextStyle(fontFamily: 'monospace'),
                          decoration: const InputDecoration(
                            labelText: 'JSON Body (optional)',
                            helperText:
                                'Bei byId stehen classId für die Klasse und ids '
                                'für die numerischen Objekt-IDs.',
                            alignLabelWithHint: true,
                            border: OutlineInputBorder(),
                          ),
                        ),
                        const SizedBox(height: 12),
                        Wrap(
                          spacing: 8,
                          runSpacing: 8,
                          children: V2ExampleEndpoint.values
                              .where((endpoint) => endpoint.acceptsBody)
                              .map(
                                (endpoint) => ElevatedButton(
                                  onPressed: _isLoggedIn && !_isChecking
                                      ? () => _executeV2Endpoint(endpoint)
                                      : null,
                                  child: Text('v2.${endpoint.label}'),
                                ),
                              )
                              .toList(growable: false),
                        ),
                        const SizedBox(height: 12),
                        Text(
                          'Letzte V2 Response',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 4),
                        Container(
                          width: double.infinity,
                          constraints: const BoxConstraints(maxHeight: 280),
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Colors.grey[100],
                            borderRadius: BorderRadius.circular(4),
                            border: Border.all(color: Colors.grey[300]!),
                          ),
                          child: SingleChildScrollView(
                            child: SelectionArea(
                              child: Text(
                                _v2Response,
                                style: const TextStyle(
                                  fontFamily: 'monospace',
                                  fontSize: 12,
                                ),
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(height: 24),
                        const Divider(),
                        const SizedBox(height: 8),
                        Text(
                          'Datei-Download (v2/file)',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 4),
                        const Text(
                          'Binärer Download über api.v2.file.get(). Bei '
                          'E-Mail-Anhängen kann die OID des Abschnitts oder '
                          'die des Anhangs verwendet werden. Leere Felder '
                          'werden NICHT als Query-Parameter gesendet.',
                        ),
                        const SizedBox(height: 12),
                        TextField(
                          key: const ValueKey<String>('v2-file-oid-field'),
                          controller: _v2FileOidController,
                          enabled: !_isChecking,
                          decoration: const InputDecoration(
                            labelText: 'Datei-OID',
                            hintText: 'z. B. 1PTF',
                            border: OutlineInputBorder(),
                          ),
                        ),
                        const SizedBox(height: 12),
                        Wrap(
                          spacing: 12,
                          runSpacing: 12,
                          children: <Widget>[
                            _buildV2FileIntField(
                              fieldKey: 'v2-file-page-field',
                              label: 'page',
                              helper: 'Seite',
                              controller: _v2FilePageController,
                            ),
                            _buildV2FileIntField(
                              fieldKey: 'v2-file-attach-item-field',
                              label: 'attachItem',
                              helper: 'E-Mail-Anhang',
                              controller: _v2FileAttachItemController,
                            ),
                            _buildV2FileIntField(
                              fieldKey: 'v2-file-zip-item-field',
                              label: 'zipItem',
                              helper: 'Item im ZIP',
                              controller: _v2FileZipItemController,
                            ),
                            _buildV2FileIntField(
                              fieldKey: 'v2-file-max-size-field',
                              label: 'maxSize',
                              helper: 'kurze Seite (px)',
                              controller: _v2FileMaxSizeController,
                            ),
                            SizedBox(
                              width: 220,
                              child: DropdownButtonFormField<bool?>(
                                key: const ValueKey<String>(
                                  'v2-file-use-pdf-field',
                                ),
                                initialValue: _v2FileUsePdf,
                                isExpanded: true,
                                decoration: const InputDecoration(
                                  labelText: 'usePdf',
                                  helperText: 'nicht senden = weglassen',
                                  border: OutlineInputBorder(),
                                ),
                                items: const <DropdownMenuItem<bool?>>[
                                  DropdownMenuItem<bool?>(
                                    value: null,
                                    child: Text('nicht senden'),
                                  ),
                                  DropdownMenuItem<bool?>(
                                    value: true,
                                    child: Text('true'),
                                  ),
                                  DropdownMenuItem<bool?>(
                                    value: false,
                                    child: Text('false'),
                                  ),
                                ],
                                onChanged: _isChecking
                                    ? null
                                    : (bool? value) {
                                        setState(() {
                                          _v2FileUsePdf = value;
                                        });
                                      },
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        ElevatedButton(
                          key: const ValueKey<String>('v2-file-get-button'),
                          onPressed: _isLoggedIn && !_isChecking
                              ? _executeV2FileGet
                              : null,
                          child: const Text('v2.file.get'),
                        ),
                        const SizedBox(height: 12),
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Colors.grey[100],
                            borderRadius: BorderRadius.circular(4),
                            border: Border.all(color: Colors.grey[300]!),
                          ),
                          child: SelectionArea(
                            child: Text(
                              _v2FileResult,
                              style: const TextStyle(
                                fontFamily: 'monospace',
                                fontSize: 12,
                              ),
                            ),
                          ),
                        ),
                        if (_v2FilePreviewBytes != null) ...<Widget>[
                          const SizedBox(height: 12),
                          ConstrainedBox(
                            constraints: const BoxConstraints(maxHeight: 240),
                            child: Image.memory(
                              _v2FilePreviewBytes!,
                              fit: BoxFit.contain,
                              errorBuilder: (_, _, _) => const Text(
                                'Bytes sind kein darstellbares Bild.',
                              ),
                            ),
                          ),
                        ],
                      ],
                    ],
                  ),
                ),
              ),
              // DOCUframe-Konfiguration
              const SizedBox(height: 16),
              SizedBox(
                height: 500,
                child: Card(
                  child: Padding(
                    padding: const EdgeInsets.all(16.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Text(
                              'Activity Log',
                              style: Theme.of(context).textTheme.headlineSmall,
                            ),
                            Spacer(),
                            IconButton(
                              icon: const Icon(Icons.clear),
                              onPressed: () {
                                setState(() {
                                  _logs.clear();
                                });
                              },
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Expanded(
                          child: Container(
                            padding: const EdgeInsets.all(8),
                            decoration: BoxDecoration(
                              color: Colors.grey[100],
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: SelectionArea(
                              child: ListView.builder(
                                itemCount: _logs.length,
                                itemBuilder: (context, index) {
                                  return Text(
                                    _logs[index],
                                    style: const TextStyle(
                                      fontFamily: 'monospace',
                                      fontSize: 12,
                                    ),
                                  );
                                },
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
