/// Der Body von `POST v3/view/action`.
///
/// Auf der Leitung steht zuerst `action`, daneben auf derselben Ebene die
/// Schlüssel von [payload]:
///
/// ```json
/// {"action": {"oid": "4TOF", "tryCount": 0}, "~StoreTime": "…", "data": {…}}
/// ```
class GsdViewActionRequest {
  /// Erstellt den Aufruf der Aktion [actionOid] im Versuch [tryCount].
  const GsdViewActionRequest({
    required this.actionOid,
    required this.tryCount,
    this.payload,
  });

  /// OID der Aktion.
  final String actionOid;

  /// Wievielter Versuch das ist; `0` beim ersten Senden.
  final int tryCount;

  /// Frei geformte Schlüssel neben `action`, unverändert gesendet. Ein
  /// Schlüssel `action` darin überschreibt den Aufruf.
  final Map<String, Object?>? payload;

  /// Der Body als JSON: `action`, dann [payload] in seiner Reihenfolge.
  Map<String, Object?> toJson() => {
    'action': {'oid': actionOid, 'tryCount': tryCount},
    ...?payload,
  };
}
