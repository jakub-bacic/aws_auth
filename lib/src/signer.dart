import 'dart:convert';

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';

import 'credentials.dart';
import 'request.dart';
import 'utils.dart';

class AWS4Signer {
  static const String ALGORITHM = 'AWS4-HMAC-SHA256';

  AWSCredentials credentials;
  String region;
  String serviceName;

  AWS4Signer(this.credentials, this.region, this.serviceName);

  void sign(
    AWSRequest request, {
    DateTime overrideDate,
  }) {
    _sign(request, overrideDate, null);
  }

  void presign(
    AWSRequest request, {
    Duration expires = const Duration(seconds: 60),
    DateTime overrideDate,
  }) {
    _sign(request, overrideDate, expires);
  }

  void _sign(
    AWSRequest request,
    DateTime overrideDate,
    Duration expires,
  ) {
    var timestamp = overrideDate ?? DateTime.now().toUtc();
    var credentialsScope = _getCredentialsScope(region, serviceName, timestamp);
    var amzCredential = credentials.accessKeyId + '/' + credentialsScope;

    // add host header if it's missing
    if (!request.headers.containsKey('Host')) {
      request.headers['Host'] = request.url.host;
    }

    if (expires != null) {
      request.queryParameters.addAll({
        'X-Amz-Algorithm': ALGORITHM,
        'X-Amz-Credential': amzCredential,
        'X-Amz-Date': formatDate(timestamp),
        'X-Amz-Expires': expires.inSeconds.toString(),
        'X-Amz-SignedHeaders': request.getSignedHeaders(),
      });

      if (credentials.sessionToken != null) {
        request.queryParameters['X-Amz-Security-Token'] =
            credentials.sessionToken;
      }
    } else {
      request.headers['X-Amz-Date'] = formatDate(timestamp);

      if (credentials.sessionToken != null) {
        request.headers['X-Amz-Security-Token'] = credentials.sessionToken;
      }
    }

    var canonicalRequest = request.getCanonicalRequest();
    var hashedCanonicalRequest =
        sha256.convert(utf8.encode(canonicalRequest)).toString();
    var signature = _calculateSignature(credentials.secretAccessId,
        hashedCanonicalRequest, region, serviceName, timestamp);

    if (expires != null) {
      request.queryParameters['X-Amz-Signature'] = signature;
    } else {
      var authorizationHeader =
          _createAuthorizationHeader(amzCredential, request, signature);
      request.headers['Authorization'] = authorizationHeader;
    }
  }

  String _createAuthorizationHeader(
    String amzCredential,
    AWSRequest request,
    String signature,
  ) {
    var result = <String>[
      '${ALGORITHM} Credential=${amzCredential}',
      'SignedHeaders=${request.getSignedHeaders()}',
      'Signature=${signature}',
    ];
    return result.join(', ');
  }

  String _calculateSignature(
    String secretAccessKey,
    String hashedCanonicalRequest,
    String region,
    String serviceName,
    DateTime timestamp,
  ) {
    var derivedSigningKey = _deriveSigningKey(
      secretAccessKey,
      region,
      serviceName,
      timestamp,
    );
    var stringToSign = _calculateStringToSign(
      region,
      serviceName,
      hashedCanonicalRequest,
      timestamp,
    );
    var sig = hmac(derivedSigningKey, stringToSign.codeUnits);
    return hex.encode(sig);
  }

  List<int> _deriveSigningKey(
    String secretAccessKey,
    String region,
    String serviceName,
    DateTime timestamp,
  ) {
    final date = formatDate(timestamp, includeTime: false);

    final kSecret = 'AWS4' + secretAccessKey;
    final kDate = hmac(kSecret.codeUnits, date.codeUnits);
    final kRegion = hmac(kDate, region.codeUnits);
    final kService = hmac(kRegion, serviceName.codeUnits);
    final kSigning = hmac(kService, 'aws4_request'.codeUnits);

    return kSigning;
  }

  String _calculateStringToSign(
    String region,
    String serviceName,
    String hashedCanonicalRequest,
    DateTime timestamp,
  ) {
    var result = <String>[
      ALGORITHM,
      formatDate(timestamp),
      _getCredentialsScope(region, serviceName, timestamp),
      hashedCanonicalRequest,
    ];
    return result.join('\n');
  }

  String _getCredentialsScope(
    String region,
    String serviceName,
    DateTime timestamp,
  ) {
    var result = <String>[
      formatDate(timestamp, includeTime: false),
      region,
      serviceName,
      'aws4_request'
    ];
    return result.join('/');
  }
}
