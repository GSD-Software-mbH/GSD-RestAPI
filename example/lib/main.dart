import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

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
  late RestApiDOCUframeManager apiManager;
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
  bool _allowSslError = false;
  bool _allowMultiRequest = false;
  bool _isConfigured = false;
  bool _isChecking = false;

  @override
  void initState() {
    super.initState();
  }

  @override
  void dispose() {
    _urlController.dispose();
    _aliasController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    _appnameController.dispose();
    super.dispose();
  }

  void _initializeApiManager(RestApiDOCUframeManager restApiDOCUframeManager) {
    // Initialize the REST API Manager
    apiManager = restApiDOCUframeManager;

    apiManager.callbacks = RestApiDOCUframeCallbacks(
      onSessionIdChanged: (sessionId) async {
        setState(() {
          _sessionId = sessionId;
          _addLog('Session ID changed: $_sessionId');
        });
      },
      onUserAndPassWrong: (exception) async {
        setState(() {
          _addLog('Authentication failed: ${exception.message}');
        });
      },
      onLicenseWrong: (exception) async {
        setState(() {
          _addLog('License error detected: ${exception.message}');
        });
      },
      onLogMessage: (message) async {
        setState(() {
          _addLog('RestApiDOCUframeManager: $message');
        });
      },
      onHttpMetricRecorded: (RestApiHttpMetric metric) async {
        setState(() {
          _addLog(
            "API Call: ${metric.path} - ${metric.duration?.inMilliseconds}ms",
          );
        });
      },
    );

    _isConfigured = true;
  }

  void _addLog(String message) {
    _logs.add('${DateTime.now().toLocal()}: $message');
    if (_logs.length > 20) {
      _logs.removeAt(0);
    }
  }

  Future<void> _checkService() async {
    try {
      setState(() {
        _status = 'Checking service...';
      });

      RestApiCheckServiceResponse response = await apiManager.checkService();

      setState(() {
        _status = response.isOk ? 'Service available' : 'Service unavailable';
        _addLog('Service check: ${response.isOk ? 'OK' : 'Failed'}');
      });
    } catch (e) {
      setState(() {
        _status = 'Service check failed';
        _addLog('Service check error: $e');
      });
    }
  }

  Future<void> _login() async {
    try {
      setState(() {
        _status = 'Logging in...';
      });

      RestApiLoginResponse loginResponse = await apiManager.login(
        _passwordController.text.toMd5Hash(),
      );

      setState(() {
        _isLoggedIn = loginResponse.isOk;
        _status = _isLoggedIn ? 'Logged in successfully' : 'Login failed';
        _sessionId = apiManager.config.sessionId;
        _addLog('Login attempt: ${_isLoggedIn ? 'Success' : 'Failed'}');
      });
    } catch (e) {
      setState(() {
        _status = 'Login error';
        _isLoggedIn = false;
        _addLog('Login error: $e');
      });
    }
  }

  Future<void> _getDocumentCount() async {
    try {
      setState(() {
        _status = 'Fetching document count...';
      });

      RestApiResponse docCountResponse = await apiManager.getObjects(
        'Dokument',
      );

      dynamic responseJson = jsonDecode(docCountResponse.httpResponse.body);

      int count = responseJson["data"]["~Count"];

      setState(() {
        if (docCountResponse.isOk) {
          _status = 'Document count fetched: $count';
          _addLog('Document count: $count');
        } else {
          _status = 'Failed to fetch document count';
          _addLog(
            'Document count fetch failed: ${docCountResponse.statusMessage}',
          );
        }
      });
    } catch (e) {
      setState(() {
        _status = 'Error fetching document count';
        _addLog('Document count error: $e');
      });
    }
  }

  Future<void> _createNote() async {
    try {
      setState(() {
        _status = 'Creating note...';
      });

      RestApiResponse createNoteResponse = await apiManager.postObject(
        'Notiz',
        jsonEncode({
          'Text': 'Dies ist eine automatisch erstellte Notiz.',
          'Name': "Testnotiz ${DateTime.now().toIso8601String()}",
          'Beschreibung': 'Notiz erstellt via GSD RestAPI Flutter Beispiel',
          '~StoreTime': DateTime.now().toISOFormatString(),
        }),
        storeMode: 10,
      );

      setState(() {
        if (createNoteResponse.isOk) {
          _addLog('Note created successfully');
        } else {
          _status = 'Failed to create note';
          _addLog('Note creation failed: ${createNoteResponse.statusMessage}');
        }
      });
    } catch (e) {
      setState(() {
        _status = 'Error creating note';
        _addLog('Note creation error: $e');
      });
    }
  }

  Future<void> _send10Requests() async {
    try {
      setState(() {
        _status = 'Sending 10 requests...';
      });

      List<Future<RestApiResponse>> futures = [];
      for (int i = 0; i < 10; i++) {
        futures.add(apiManager.getObjects("Dokument"));
      }

      List<RestApiResponse> responses = await Future.wait(futures);

      _addLog('Sent 10 simultaneous requests');
      for (int i = 0; i < responses.length; i++) {
        if (responses[i].isOk) {
          dynamic responseJson = jsonDecode(responses[i].httpResponse.body);
          int count = responseJson["data"]["~Count"];
          _addLog('Request ${i + 1}: Document count: $count');
        } else {
          _addLog('Request ${i + 1}: Failed - ${responses[i].statusMessage}');
        }
      }

      setState(() {
        if (responses.any((response) => !response.isOk)) {
          _addLog('Note created successfully');
        } else {
          _status = 'Error sending 10 requests';
          _addLog('Error sending 10 requests');
        }
      });
    } catch (e) {
      setState(() {
        _status = 'Error sending 10 requests';
        _addLog('Error sending 10 requests: $e');
      });
    }
  }

  Future<void> _checkSession() async {
    try {
      setState(() {
        _status = 'Checking session...';
      });

      RestApiResponse sessionResponse = await apiManager.checkSession();

      setState(() {
        _status = sessionResponse.isOk ? 'Session valid' : 'Session invalid';
        _addLog('Session check: ${sessionResponse.isOk ? 'Valid' : 'Invalid'}');
      });
    } catch (e) {
      setState(() {
        _status = 'Session check failed';
        _addLog('Session check error: $e');
      });
    }
  }

  Future<void> _logout() async {
    try {
      setState(() {
        _status = 'Logging out...';
      });

      await apiManager.logout();

      setState(() {
        _isLoggedIn = false;
        _sessionId = 'None';
        _status = 'Logged out';
        _addLog('Logged out successfully');
      });
    } catch (e) {
      setState(() {
        _status = 'Logout error';
        _addLog('Logout error: $e');
      });
    }
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

  /// Überprüft die DOCUframe-Verbindung
  Future<void> _checkDOCUframeConnection() async {
    setState(() {
      _isChecking = true;
    });

    try {
      final restApiManager = RestApiDOCUframeManager(
        config: RestApiDOCUframeConfig(
          appKey: "123",
          userName: _usernameController.text,
          appNames: [_appnameController.text],
          serverUrl: _urlController.text,
          alias: _aliasController.text,
          allowSslError: _allowSslError,
          device: RestApiDevice('gsd_utilities_example_app'),
          multiRequest: _allowMultiRequest,
          bufferFlushDelayMs: int.parse(_bufferFlushDelayController.text),
        ),
      );

      // Führe Check-Service aus
      final checkResult = await restApiManager.checkService();

      if (checkResult.isOk) {
        final loginResult = await restApiManager.login(
          _passwordController.text,
        );

        if (loginResult.isOk) {
          _initializeApiManager(restApiManager);
        } else {
          _showErrorDialog(
            'Login fehlgeschlagen',
            'Fehler: ${loginResult.statusMessage}\nBitte überprüfen Sie die Zugangsdaten.',
          );
          setState(() {
            _isChecking = false;
          });
          return;
        }
      } else {
        _showErrorDialog(
          'Verbindung fehlgeschlagen',
          'Der DOCUframe-Service ist nicht erreichbar.\nStatus: ${checkResult.httpResponse.statusCode}\nBitte überprüfen Sie die Konfiguration.',
        );
      }
    } catch (e) {
      _showErrorDialog('Verbindungsfehler', 'Fehler beim Verbindungstest:\n$e');
    } finally {
      setState(() {
        _isChecking = false;
      });
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
                                Text(
                                  'RestApiDOCUframeManager konfigurieren',
                                  style: Theme.of(
                                    context,
                                  ).textTheme.headlineSmall,
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
                              ], //
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
                              subtitle: const Text(
                                'Aktivieren um mehrere Anfragen in einer HTTP-Verbindung zu bündeln',
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

                                        _checkDOCUframeConnection();
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
                                      ? 'Verbindung prüfen...'
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
                        children: [
                          ElevatedButton(
                            onPressed: _checkService,
                            child: const Text('Check Service'),
                          ),
                          ElevatedButton(
                            onPressed: _login,
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
                            onPressed: _isLoggedIn ? _send10Requests : null,
                            child: const Text('Send 10 Requests'),
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
