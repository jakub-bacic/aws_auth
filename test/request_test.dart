import 'dart:convert';

import 'package:aws_auth/src/request.dart';
import 'package:test/test.dart';

AWSRequest createTestRequest(
  String url, {
  String method = 'GET',
  Map<String, String> headers = const {},
  List<int> payload = const [],
}) {
  return AWSRequest(
    url,
    method: method,
    headers: headers,
    body: payload,
  );
}

void main() {
  group('AWSRequest:basic', () {
    test('Create request object directly', () {
      var request = AWSRequest(
        Uri.parse('https://sts.amazonaws.com/foo/bar/baz'),
        body: utf8.encode('foo bar'),
        headers: {'My-Header': 'header-value'},
        method: 'post',
        queryParameters: {'My-Param': 'query-value'},
      );
      expect(request.host, 'sts.amazonaws.com');
      expect(request.path, '/foo/bar/baz');
      expect(request.queryParameters['My-Param'], 'query-value');
      expect(request.headers['My-Header'], 'header-value');
      expect(request.method, 'POST');
      expect(request.body, 'foo bar');
    });

    test('Create request object directly (using String as url)', () {
      var request = AWSRequest(
        'https://sts.amazonaws.com/foo/bar/baz',
        body: utf8.encode('foo bar'),
        headers: {'My-Header': 'header-value'},
        method: 'post',
        queryParameters: {'My-Param': 'query-value'},
      );
      expect(request.host, 'sts.amazonaws.com');
      expect(request.path, '/foo/bar/baz');
      expect(request.queryParameters['My-Param'], 'query-value');
      expect(request.headers['My-Header'], 'header-value');
      expect(request.method, 'POST');
      expect(request.body, 'foo bar');
    });

    test('Create form-encoded body', () {
      var request = AWSRequest.formData(
        'https://sts.amazonaws.com',
        body: {
          'Action': 'GetCallerIdentity',
          'Version': '2011-06-15',
        },
      );
      expect(request.body, 'Action=GetCallerIdentity&Version=2011-06-15');
      expect(request.contentType,
          'application/x-www-form-urlencoded; charset=UTF-8');
    });

    test('Create JSON body', () {
      var request = AWSRequest.json(
        'https://sts.amazonaws.com',
        body: {
          'Action': 'GetCallerIdentity',
          'Version': '2011-06-15',
        },
      );
      expect(request.body,
          '{"Action":"GetCallerIdentity","Version":"2011-06-15"}');
      expect(request.contentType, 'application/json; charset=UTF-8');
    });

    test('Headers should be case insensitive', () {
      var request = createTestRequest(
        'https://sts.amazonaws.com',
        headers: {'My-Header': 'header-value'},
      );
      expect(request.headers['My-Header'], 'header-value');
      expect(request.headers['my-header'], 'header-value');

      request.headers['my-header'] = 'changed-value';
      expect(request.headers['My-Header'], 'changed-value');
      expect(request.headers['my-header'], 'changed-value');
    });
  });

  group('AWSRequest:canonicalQueryString', () {
    test('Empty query string', () {
      var request = createTestRequest('https://sts.amazonaws.com');
      expect(request.getCanonicalQueryString(), '');
    });

    test('Sort parameter names', () {
      var request = createTestRequest('https://sts.amazonaws.com?c=3&a=1&b=2');
      expect(request.getCanonicalQueryString(), 'a=1&b=2&c=3');
    });

    test('Sort parameter names (lowercase and uppercase)', () {
      var request =
          createTestRequest('https://sts.amazonaws.com?b=4&a=3&B=2&A=1');
      expect(request.getCanonicalQueryString(), 'A=1&B=2&a=3&b=4');
    });

    test('Encode values', () {
      var request =
          createTestRequest('https://sts.amazonaws.com?a=value+with+spaces');
      expect(request.getCanonicalQueryString(), 'a=value%20with%20spaces');
    });
  });

  group('AWSRequest:canonicalHeaders', () {
    test('Lowercase header names', () {
      var request = createTestRequest(
        'https://sts.amazonaws.com',
        headers: {
          'My-Header-Key': 'value',
        },
      );
      expect(request.getCanonicalHeaders(), 'my-header-key:value\n');
    });

    test('Trim leading and trailing spaces', () {
      var request = createTestRequest(
        'https://sts.amazonaws.com',
        headers: {
          'foo': '   leading and trailing   ',
        },
      );
      expect(request.getCanonicalHeaders(), 'foo:leading and trailing\n');
    });

    test('Collapse multiple spaces', () {
      var request = createTestRequest(
        'https://sts.amazonaws.com',
        headers: {
          'foo': 'double  space',
        },
      );
      expect(request.getCanonicalHeaders(), 'foo:double space\n');
    });

    test('Sort headers', () {
      var request = createTestRequest(
        'https://sts.amazonaws.com',
        headers: {
          'c': '3',
          'b': '2',
          'a': '1',
        },
      );

      var canonicalHeaders = request.getCanonicalHeaders();
      var expected = 'a:1\n'
          'b:2\n'
          'c:3\n';
      expect(canonicalHeaders, expected);
    });
  });

  group('AWSRequest:signedHeaders', () {
    test('Single header', () {
      var request = createTestRequest(
        'https://sts.amazonaws.com',
        headers: {
          'Foo': 'value',
        },
      );
      expect(request.getSignedHeaders(), 'foo');
    });

    test('Multiple headers', () {
      var request = createTestRequest(
        'https://sts.amazonaws.com',
        headers: {
          'c': '3',
          'b': '2',
          'a': '1',
        },
      );
      expect(request.getSignedHeaders(), 'a;b;c');
    });
  });

  group('AWSRequest:hashedPayload', () {
    test('Empty payload', () {
      var request = createTestRequest('https://sts.amazonaws.com');
      expect(request.getHashedPayload(),
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    test('Sample payload', () {
      var payload = utf8.encode('foo\nbar');
      var request =
          createTestRequest('https://sts.amazonaws.com', payload: payload);
      expect(request.getHashedPayload(),
          '807eff6267f3f926a21d234f7b0cf867a86f47e07a532f15e8cc39ed110ca776');
    });
  });

  test('AWSRequest:canonicalRequest', () {
    // example from https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    var request = createTestRequest(
      'https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08',
      headers: {
        'Host': 'iam.amazonaws.com',
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
        'X-Amz-Date': '20150830T123600Z',
      },
    );

    var canonicalRequest = request.getCanonicalRequest();
    var expected = 'GET\n'
        '/\n'
        'Action=ListUsers&Version=2010-05-08\n'
        'content-type:application/x-www-form-urlencoded; charset=utf-8\n'
        'host:iam.amazonaws.com\n'
        'x-amz-date:20150830T123600Z\n'
        '\n'
        'content-type;host;x-amz-date\n'
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    expect(canonicalRequest, expected);
  });
}
