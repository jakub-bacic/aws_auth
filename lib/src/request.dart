import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'utils.dart';

/// An AWS API HTTP request.
class AWSRequest {
  /// The scheme of the request URI.
  final String scheme;

  /// The HTTP method of the request.
  final String method;

  /// The host name of the request URI.
  final String host;

  /// The path of the request URI.
  final String path;

  /// The query parameters of the request.
  Map<String, String> queryParameters;

  /// The HTTP headers of the request.
  final Headers headers;

  /// The body of the request as bytes.
  final Uint8List bodyBytes;

  /// The body of the request as string (assumes UTF-8 encoding).
  String get body => utf8.decode(bodyBytes);

  /// The content type header value of the request.
  String? get contentType => headers['Content-Type'];

  set contentType(String? value) {
    if (value != null) {
      headers['Content-Type'] = value;
    }
  }

  /// The URI of the request.
  Uri get url {
    return Uri(
      scheme: scheme,
      host: host,
      queryParameters: queryParameters.isNotEmpty ? queryParameters : null,
      path: path,
    );
  }

  /// Creates a new HTTP request.
  factory AWSRequest(
    dynamic url, {
    String? method,
    Map<String, String>? queryParameters,
    Map<String, String>? headers,
    List<int>? body,
  }) {
    final uri = _fromUriOrString(url);

    return AWSRequest._(
      uri.scheme.isNotEmpty ? uri.scheme : 'https',
      method?.toUpperCase() ?? 'GET',
      uri.host,
      uri.path,
      queryParameters ?? Map<String, String>.from(uri.queryParameters),
      headers != null ? Headers.from(headers) : Headers(),
      body != null ? Uint8List.fromList(body) : Uint8List(0),
    );
  }

  /// Creates a new HTTP request with url-encoded form data
  /// based on `params` argument.
  ///
  /// It automatically sets the method to 'POST' and `content-type`
  /// header value to `application/x-www-form-urlencoded; charset=UTF-8`.
  factory AWSRequest.formData(
    dynamic url, {
    Map<String, dynamic>? body,
    Map<String, String>? queryParameters,
    Map<String, String>? headers,
  }) {
    var request = AWSRequest(
      url,
      method: 'POST',
      queryParameters: queryParameters,
      headers: headers,
      body:
          body != null ? utf8.encode(_createFormDataBody(body)) : Uint8List(0),
    );

    // override content-type header
    request.contentType = 'application/x-www-form-urlencoded; charset=UTF-8';

    return request;
  }

  /// Creates a new HTTP request with json payload
  /// based on `body` argument.
  ///
  /// It automatically sets `content-type` header value
  /// to `application/json; charset=UTF-8`.
  factory AWSRequest.json(
    dynamic url, {
    String? method,
    dynamic? body,
    Map<String, String>? queryParameters,
    Map<String, String>? headers,
  }) {
    var request = AWSRequest(
      url,
      method: method,
      queryParameters: queryParameters,
      headers: headers,
      body: utf8.encode(jsonEncode(body)),
    );

    // override content-type header
    request.contentType = 'application/json; charset=UTF-8';

    return request;
  }

  /// Returns canonical URI parameter
  ///
  /// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
  String getCanonicalUri() {
    var normalizedPath = normalizePath(path);
    return quote(normalizedPath).replaceAll('%2F', '/');
  }

  /// Returns canonical query string
  ///
  /// See: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
  String getCanonicalQueryString() {
    var result = <String>[];

    var sortedKeys = queryParameters.keys.toList()..sort();
    sortedKeys.forEach((key) {
      final value = queryParameters[key]!;
      result.add('${quote(key)}=${quote(value)}');
    });

    return result.join('&');
  }

  /// Returns canonical headers
  ///
  /// See: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
  String getCanonicalHeaders() {
    var result = <String>[];

    var canonicalHeadersMap = headers
        .map((key, value) => MapEntry(key.toLowerCase(), trimAll(value)));
    var sortedKeys = canonicalHeadersMap.keys.toList()..sort();
    for (var key in sortedKeys) {
      var value = canonicalHeadersMap[key];
      result.add('$key:$value\n');
    }

    return result.join();
  }

  /// Returns signed headers
  ///
  /// See: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
  String getSignedHeaders() {
    var result = <String>[];

    var sortedKeys = headers.keys.map((e) => e.toLowerCase()).toList()..sort();
    for (var key in sortedKeys) {
      result.add(key);
    }

    return result.join(';');
  }

  /// Returns hashed payload
  ///
  /// See: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
  String getHashedPayload() {
    if (bodyBytes.isEmpty) {
      // precalculated SHA256 value for empty string
      return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    }

    return sha256.convert(bodyBytes).toString();
  }

  /// Return canonical request form
  ///
  /// See: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
  String getCanonicalRequest({
    bool signPayload = true,
  }) {
    var result = <String>[
      method.toUpperCase(),
      getCanonicalUri(),
      getCanonicalQueryString(),
      getCanonicalHeaders(),
      getSignedHeaders(),
      signPayload ? getHashedPayload() : 'UNSIGNED-PAYLOAD',
    ];
    return result.join('\n');
  }

  AWSRequest._(
    this.scheme,
    this.method,
    this.host,
    this.path,
    this.queryParameters,
    this.headers,
    this.bodyBytes,
  );

  static String _createFormDataBody(Map<String, dynamic> params) {
    final parts = <String>[];
    params.forEach((key, value) {
      parts.add(
        '${Uri.encodeQueryComponent(key)}='
        '${Uri.encodeQueryComponent(value.toString())}',
      );
    });
    return parts.join('&');
  }

  static Uri _fromUriOrString(dynamic url) =>
      url is String ? Uri.parse(url) : url as Uri;
}
