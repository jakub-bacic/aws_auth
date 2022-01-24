import 'dart:io';
import 'package:aws_auth/aws_auth.dart';
import 'package:http/http.dart' as http;

const AWS_KEY = 'YOUR_AWS_KEY';
const AWS_SECRET = 'YOUR_AWS_SECRET';
const AWS_REGION = 'region';
const BUCKET_NAME = 'BUCKET';

AWSRequest createPresignS3Request(
    AWS4Signer signer,
    Duration expires,
    String bucketName,
    String bucketPath,
    {bool public = false}
    ) {
  // create request
  final req = AWSRequest(
      //'https://$bucketName.${signer.region}.digitaloceanspaces.com$bucketPath',
      'https://$bucketName.s3.${signer.region}.amazonaws.com$bucketPath',
      method: 'PUT',
      headers: {
        if (public)
          'x-amz-acl': 'public-read'
      }
  );

  // presign the request
  signer.presign(req, expires: expires);

  return req;
}

Uri presignedAWS(String path, {bool public = false}) {
  final credentialsProvider = AWSStaticCredentialsProvider(
    AWS_KEY,
    AWS_SECRET,
    sessionToken: null,
  );
  final signer = AWS4Signer(
    credentialsProvider,
    region: AWS_REGION,
    serviceName: 's3',
  );

  final presignedReq = createPresignS3Request(
      signer,
      Duration(minutes: 5),
      BUCKET_NAME,
      path,
    public: public
  );

  return presignedReq.url;
}

Future<void> main() async {
  final uri = presignedAWS('/test/README.md', public: true);

  final uploaded = await http.put(uri,
      body: await File('README.md').readAsBytes(), headers: {
        'x-amz-acl': 'public-read'
      });

  print('Status: ${uploaded.statusCode}');
}
