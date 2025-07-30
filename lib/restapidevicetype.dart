enum RestApiDeviceType {
  unkown(0),
  android(100),
  ios(200),
  web(300);

  final int id;

  const RestApiDeviceType(this.id);

}