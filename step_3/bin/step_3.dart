import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/src/utils.dart';

void main(List<String> arguments) async {
  final port = _handledParsing(arguments);

  ServerSocket serverSocket = await ServerSocket.bind(
    InternetAddress.anyIPv4,
    port,
  );

  print(
    'Server[🔁]: is running on ${serverSocket.address.address}:${serverSocket.port}',
  );

  await for (var socket in serverSocket) {
    _handleClient(socket);
  }
}

int _handledParsing(List<String> arguments) {
  var parser = ArgParser()
    ..addOption(
      'port',
      abbr: 'p',
      defaultsTo: '8888',
      callback: (value) {
        if (value != null) {
          var port = int.tryParse(value);
          if (port == null || port < 0 || port > 65535) {
            print('Invalid port number: $value');
            exit(64);
          }
        }
      },
      help: 'Port to listen on',
    )
    ..addFlag(
      'help',
      abbr: 'h',
      help: 'Show this help message',
      negatable: false,
    );

  var results = parser.parse(arguments);
  if (results['help'] as bool) {
    print(parser.usage);
    exit(64);
  }

  return int.parse(results['port']);
}

SecureRandom getSecureRandom() {
  final secureRandom = FortunaRandom();

  final seed = Uint8List(32);
  final random = Random.secure();

  for (int i = 0; i < seed.length; i++) {
    seed[i] = random.nextInt(256);
  }

  secureRandom.seed(KeyParameter(Uint8List.fromList(seed)));
  return secureRandom;
}

BigInt _randomExponent(int bits, SecureRandom rng) {
  return rng.nextBigInteger(bits);
}

// handle el professor function
// Convert Bigint into Uint8List using PC function
// Oposite of decodeBigInt function from PC
Uint8List _toFixedLengh(BigInt number, int length) {
  Uint8List bytes = encodeBigInt(number);

  if (bytes.length == length) {
    return bytes;
  }

  if (bytes.length > length) {
    return bytes.sublist(bytes.length - length);
  }

  Uint8List result = Uint8List(length);
  result.setRange(length - bytes.length, length, bytes);
  return result;
}

Uint8List _createX509SPKI(RSAPublicKey publicKey) {
  // Placeholder for X.509 / SubjectPublicKeyInfo DER generation
  //create structure  pkcs1 = SEQUENCE { modulus INTEGER, exponent INTEGER }
  final pkcs1Key = ASN1Sequence()
    ..add(ASN1Integer(publicKey.modulus!))
    ..add(ASN1Integer(publicKey.exponent!));

  //encode pkcs1 to DER
  final pkcs1KeyBytes = pkcs1Key.encode();

  //adding the algorithm identifier for RSA encryption
  final algId = ASN1AlgorithmIdentifier(
    ASN1ObjectIdentifier.fromName("rsaEncryption"),
  );

  //create the SubjectPublicKeyInfo structure
  final spki = ASN1Sequence()
    ..add(algId)
    ..add(ASN1BitString(stringValues: pkcs1KeyBytes));

  return spki.encode();
}

Uint8List _mgf1SHA1(Uint8List seed, int maskLen) {
  final digest = SHA1Digest();
  final hLen = digest.digestSize;
  final output = <int>[];

  for (int counter = 0; output.length < maskLen; counter++) {
    final c = Uint8List(4);
    c[0] = (counter >> 24) & 0xff;
    c[1] = (counter >> 16) & 0xff;
    c[2] = (counter >> 8) & 0xff;
    c[3] = counter & 0xff;

    digest.reset();
    digest.update(seed, 0, seed.length);
    digest.update(c, 0, c.length);

    final hash = Uint8List(hLen);
    digest.doFinal(hash, 0);
    output.addAll(hash);
  }

  return Uint8List.fromList(output.sublist(0, maskLen));
}

Uint8List _oaepSHA256Decrypt(Uint8List ciphertext, RSAPrivateKey privateKey) {
  // Java utilise SHA-256 pour le hash principal et SHA-1 pour MGF1 par défaut
  final digest = SHA256Digest();
  final hLen = digest.digestSize; // 32 bytes

  // Déchiffrer avec RSA
  final rsaEngine = RSAEngine()
    ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));

  var em = rsaEngine.process(ciphertext);
  final k = (privateKey.modulus!.bitLength + 7) ~/ 8;

  // Si em.length < k, ajouter des zéros au début
  if (em.length < k) {
    final paddedEm = Uint8List(k);
    paddedEm.setRange(k - em.length, k, em);
    em = paddedEm;
  }

  if (em.length != k || k < 2 * hLen + 2) {
    throw ArgumentError('Decryption error: invalid length');
  }

  // em = 0x00 || maskedSeed || maskedDB
  if (em[0] != 0) {
    throw ArgumentError('Decryption error: first byte not zero (${em[0]})');
  }

  final maskedSeed = em.sublist(1, hLen + 1);
  final maskedDB = em.sublist(hLen + 1);

  // seedMask = MGF1-SHA1(maskedDB, hLen) - Java utilise SHA-1 pour MGF1
  final seedMask = _mgf1SHA1(maskedDB, hLen);

  // seed = maskedSeed XOR seedMask
  final seed = Uint8List(hLen);
  for (int i = 0; i < hLen; i++) {
    seed[i] = maskedSeed[i] ^ seedMask[i];
  }

  // dbMask = MGF1-SHA1(seed, k - hLen - 1)
  final dbMask = _mgf1SHA1(seed, k - hLen - 1);

  // DB = maskedDB XOR dbMask
  final db = Uint8List(maskedDB.length);
  for (int i = 0; i < maskedDB.length; i++) {
    db[i] = maskedDB[i] ^ dbMask[i];
  }

  // DB = lHash || PS || 0x01 || M
  // lHash = SHA-256("") pour label vide
  final lHash = digest.process(Uint8List(0));

  // Vérifier lHash
  for (int i = 0; i < hLen; i++) {
    if (db[i] != lHash[i]) {
      throw ArgumentError('Decryption error: lHash mismatch');
    }
  }

  // Chercher 0x01
  int index = hLen;
  while (index < db.length && db[index] == 0) {
    index++;
  }

  if (index >= db.length || db[index] != 1) {
    throw ArgumentError('Decryption error: no 0x01 separator found');
  }

  // Message commence après 0x01
  return db.sublist(index + 1);
}

Uint8List _oaepSHA256Encrypt(Uint8List message, RSAPublicKey publicKey) {
  // Java utilise SHA-256 pour le hash principal et SHA-1 pour MGF1
  final digest = SHA256Digest();
  final hLen = digest.digestSize; // 32 bytes
  final k = (publicKey.modulus!.bitLength + 7) ~/ 8;
  final mLen = message.length;

  if (mLen > k - 2 * hLen - 2) {
    throw ArgumentError('Message too long for RSA key size');
  }

  // lHash = SHA-256("") pour label vide
  final lHash = digest.process(Uint8List(0));

  // DB = lHash || PS || 0x01 || M
  final psLen = k - mLen - 2 * hLen - 2;
  final db = Uint8List(k - hLen - 1);
  db.setRange(0, hLen, lHash);
  // PS est déjà des zéros
  db[hLen + psLen] = 1;
  db.setRange(hLen + psLen + 1, db.length, message);

  // Générer seed aléatoire
  final rng = getSecureRandom();
  final seed = rng.nextBytes(hLen);

  // dbMask = MGF1-SHA1(seed, k - hLen - 1)
  final dbMask = _mgf1SHA1(seed, k - hLen - 1);

  // maskedDB = DB XOR dbMask
  final maskedDB = Uint8List(db.length);
  for (int i = 0; i < db.length; i++) {
    maskedDB[i] = db[i] ^ dbMask[i];
  }

  // seedMask = MGF1-SHA1(maskedDB, hLen)
  final seedMask = _mgf1SHA1(maskedDB, hLen);

  // maskedSeed = seed XOR seedMask
  final maskedSeed = Uint8List(hLen);
  for (int i = 0; i < hLen; i++) {
    maskedSeed[i] = seed[i] ^ seedMask[i];
  }

  // em = 0x00 || maskedSeed || maskedDB
  final em = Uint8List(k);
  em[0] = 0;
  em.setRange(1, hLen + 1, maskedSeed);
  em.setRange(hLen + 1, k, maskedDB);

  // Chiffrer avec RSA
  final rsaEngine = RSAEngine()
    ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));

  return rsaEngine.process(em);
}

void _handleClient(Socket socket) {
  socket.setOption(SocketOption.tcpNoDelay, true);

  final BigInt G = BigInt.from(2);
  final BigInt P = BigInt.parse(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    radix: 16,
  );
  final salt = Uint8List.fromList('phase3 aead key '.codeUnits);
  final pbkdf2Iterations = 600000;
  final rng = getSecureRandom();

  BigInt prkb = _randomExponent(256, rng);
  final BigInt pkb = G.modPow(prkb, P);
  BigInt? pka;
  BigInt? Z;

  Uint8List? aesKey;
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>? pair;

  Uint8List? transcriptHash;
  RSAPublicKey? pubc;

  utf8.decoder
      .bind(socket)
      .transform(const LineSplitter())
      .listen(
        (line) async {
          if (line.contains(':')) {
            var head = line.split(':')[0];
            var body = line.split(':')[1];

            switch (head) {
              case 'A':
                pka = decodeBigInt(base64.decode(body));
                var B = base64.encode(_toFixedLengh(pkb, 256));
                print('Client[🔑 - A]: $body');
                print('Server[🔑 - B]: $B');
                socket.writeln('B:$B');

                Z = pka!.modPow(prkb, P);
                print('Server[🔑 - Z]: $Z');

                print('Server[🔑 - DERIVING KEY]');
                var sha256 = SHA256Digest();
                var list = Uint8List.fromList([
                  ..._toFixedLengh(G, 1),
                  ..._toFixedLengh(P, 256),
                  ..._toFixedLengh(pka!, 256),
                  ..._toFixedLengh(pkb, 256),
                ]);

                transcriptHash = sha256.process(list);
                var password = base64.encode(transcriptHash!);
                print('Server[🔑 - PASSWORD]: $password');

                var pbkdf2 = KeyDerivator('SHA-256/HMAC/PBKDF2')
                  ..init(Pbkdf2Parameters(salt, pbkdf2Iterations, 32));

                print('Server[🔑 - AES_KEY] - Deriving key from password');
                aesKey = pbkdf2.process(utf8.encode(password));

                final rsaGen = RSAKeyGenerator()
                  ..init(
                    ParametersWithRandom(
                      RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64),
                      rng,
                    ),
                  );

                pair = rsaGen.generateKeyPair();
                final publicKey = pair!.publicKey;
                final privateKey = pair!.privateKey;

                var pubs = base64.encode(
                  pair!.publicKey.modulus.toString().codeUnits,
                );
                print('Server[🔑 - PUBS]: $pubs');

                final nonce = rng.nextBytes(12);
                print('Server[🔑 - NONCE]: ${base64.encode(nonce)}');

                final gcm = GCMBlockCipher(AESEngine())
                  ..init(
                    true,
                    AEADParameters(
                      KeyParameter(aesKey!),
                      128,
                      nonce,
                      transcriptHash!,
                    ),
                  );

                //wanna die, got to generate a X.509 / SubjectPublicKeyInfo DER  from scratch
                final derS = _createX509SPKI(publicKey);
                print('Server[🔑 - SPKI DER]: ${base64.encode(derS)}');

                final nonceAndCt = Uint8List.fromList([
                  ...nonce,
                  ...gcm.process(derS),
                ]);

                print('Server[🔑 - NONCE+CT]: ${base64.encode(nonceAndCt)}');
                socket.writeln('PUBS:${base64.encode(nonceAndCt)}');

              case 'PUBC':
                print('Client[🔑 - PUBC]: $body');

                try {
                  final blob = base64.decode(body);
                  if (transcriptHash == null || aesKey == null) {
                    throw Exception(
                      'Missing transcript/aes key (send A first)',
                    );
                  }

                  final nonce = blob.sublist(0, 12);
                  final ct = blob.sublist(12);

                  final gcm = GCMBlockCipher(AESEngine())
                    ..init(
                      false,
                      AEADParameters(
                        KeyParameter(aesKey!),
                        128,
                        nonce,
                        transcriptHash!,
                      ),
                    );

                  final derC = gcm.process(ct);
                  print('Client[🔑 - DERC]: ${base64.encode(derC)}');

                  //Extract modulus and exponent from DER
                  final asn1Parser = ASN1Parser(derC);
                  final spki = asn1Parser.nextObject() as ASN1Sequence;

                  final pkcs1key = spki.elements![1] as ASN1BitString;
                  final pkcs1Parser = ASN1Parser(
                    pkcs1key.stringValues as Uint8List,
                  );
                  final pkcs1Seq = pkcs1Parser.nextObject() as ASN1Sequence;
                  print('Client[🔑 - PKCS1SEQ]: $pkcs1Seq');
                  print(
                    'Client[🔑 - ELEMENTS 1]: ${(pkcs1Seq.elements![0].encodedBytes).toString()}',
                  );
                  print(
                    'Client[🔑 - ELEMENTS 2]: ${(pkcs1Seq.elements![1].encodedBytes).toString()}',
                  );

                  final modulusElement = pkcs1Seq.elements![0] as ASN1Integer;
                  final exponentElement = pkcs1Seq.elements![1] as ASN1Integer;

                  final modulus = modulusElement.integer!;
                  final exponent = exponentElement.integer!;

                  print('Client[🔑 - MODULUS]: $modulus');
                  print('Client[🔑 - EXPONENT]: $exponent');
                  pubc = RSAPublicKey(modulus, exponent);
                } catch (e) {
                  print('Server[❌ - ERROR]: Failed to process PUBC - $e');
                }

              case "CT_RSA":
                print('Client[🔐 - CT_RSA]: $body');
                try {
                  final cipherText = base64.decode(body);
                  if (pair == null) {
                    throw Exception('Missing server key pair (generate first)');
                  }
                  if (pubc == null) {
                    throw Exception(
                      'Missing client public key (process PUBC first)',
                    );
                  }

                  //1) Decrypter le message
                  final decrypted = _oaepSHA256Decrypt(
                    cipherText,
                    pair!.privateKey,
                  );
                  final message = utf8.decode(decrypted);
                  print('Server[🔓 - MESSAGE]: $message');

                  // 2) Signature du message avec RSA-PSS
                  final rsaSalt = rng.nextBytes(32);
                  final signer =
                      PSSSigner(
                        RSAEngine(),
                        SHA256Digest(),
                        SHA256Digest(), // MGF1 avec SHA-256
                      )..init(
                        true,
                        ParametersWithSalt(
                          PrivateKeyParameter<RSAPrivateKey>(pair!.privateKey),
                          rsaSalt,
                        ),
                      );

                  final signature = signer.generateSignature(
                    utf8.encode(message),
                  );
                  final sigBytes = signature.bytes;
                  print('Server[🔏 - SIGNATURE]: ${base64.encode(sigBytes)}');
                  print('Server[🔏 - SIGNATURE LENGTH]: ${sigBytes.length}');

                  // Découper en 2 morceaux de 128 bytes
                  final sig1 = sigBytes.sublist(0, 128);
                  final sig2 = sigBytes.sublist(128, 256);

                  final ctSig1 = _oaepSHA256Encrypt(sig1, pubc!);
                  final ctSig2 = _oaepSHA256Encrypt(sig2, pubc!);

                  print('Server[📤 - SIG1]: ${base64.encode(ctSig1)}');
                  socket.writeln('SIG1:${base64.encode(ctSig1)}');

                  print('Server[📤 - SIG2]: ${base64.encode(ctSig2)}');
                  socket.writeln('SIG2:${base64.encode(ctSig2)}');
                } catch (e) {
                  print('Server[❌ - ERROR]: Failed to decrypt CT_RSA - $e');
                }

              case _:
                print('Client[❓ - UNKNOWN]: $line');
            }
          }
        },
        onDone: () => print(
          'Server[🛑 - CLOSING]: Connection with ${socket.remoteAddress.address}:${socket.remotePort} closed',
        ),
        onError: (error) => print(
          'Server[❌ - ERROR]: Error occurred with ${socket.remoteAddress.address}:${socket.remotePort} - $error',
        ),
      );
}
