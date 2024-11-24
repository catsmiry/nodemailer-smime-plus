const forge = require('node-forge');
const MimeNode = require('nodemailer/lib/mime-node/index.js');
const fs = require('fs');

module.exports = function (options) {
  return function (mail, callback) {
    // Create new root node
    const rootNode = new MimeNode('multipart/signed; protocol="application/pkcs7-signature"; micalg=sha256;');

    // Append existing node
    const contentNode = rootNode.appendChild(mail.message);

    // Pull up existing headers (except Content-Type)
    const contentHeaders = contentNode._headers;
    for (let i = 0, len = contentHeaders.length; i < len; i++) {
      const header = contentHeaders[i];
      if (header.key.toLowerCase() === 'content-type') {
        continue;
      }
      rootNode.setHeader(header.key, header.value);
      contentHeaders.splice(i, 1);
      i--;
      len--;
    }

    // Need to crawl all child nodes and apply canonicalization to all text/* nodes
    // Otherwise mail agents may complain the message has been tampered with
    canonicalTransform(contentNode);

    // Build content node for digest generation
    contentNode.build((err, buf) => {
      if (err) {
        return callback(err);
      }

      // Read the certificate from a file if it's a path
      let cert;
      if (typeof options.cert === 'string') {
        try {
          cert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(fs.readFileSync(options.cert, 'utf8')));
        } catch (error) {
          return callback(new Error('Failed to read certificate from file: ' + error.message));
        }
      } else {
        cert = options.cert;
      }

      // Handle the key: convert string (passphrase) to PrivateKey if needed
      let privateKey;
      if (typeof options.key === 'string') {
        // options.keyがパスフレーズとして渡される場合、秘密鍵を読み込む
        try {
          const privateKeyPem = fs.readFileSync(options.key, 'utf8'); // パスフレーズではなく秘密鍵のファイルパスを想定
          privateKey = forge.pki.privateKeyFromPem(privateKeyPem); // PEM形式からPrivateKeyを生成
        } catch (error) {
          return callback(new Error('Failed to read or convert key from PEM: ' + error.message));
        }
      } else {
        privateKey = options.key; // 既にPrivateKey型の場合
      }

      // Generate PKCS7 ASN.1
      const p7 = forge.pkcs7.createSignedData();
      p7.content = forge.util.createBuffer(buf.toString('binary'));
      p7.addCertificate(cert);
      
      // Check if options.chain exists and is an array before iterating
      if (Array.isArray(options.chain)) {
        options.chain.forEach(cert => {
          p7.addCertificate(cert);
        });
      }
      
      p7.addSigner({
        key: privateKey, // ここでPrivateKeyを使用
        certificate: cert,
        digestAlgorithm: forge.pki.oids.sha256,
        authenticatedAttributes: [
          {
            type: forge.pki.oids.contentType,
            value: forge.pki.oids.data,
          },
          {
            type: forge.pki.oids.messageDigest,
          },
          {
            type: forge.pki.oids.signingTime,
          },
        ],
      });
      p7.sign();
      const asn1 = p7.toAsn1();

      // Scrub encapContentInfo.eContent
      asn1.value[1].value[0].value[2].value.splice(1, 1);

      // Write PKCS7 ASN.1 as DER to buffer
      const der = forge.asn1.toDer(asn1);
      const derBuffer = Buffer.from(der.getBytes(), 'binary');

      // Append signature node
      const signatureNode = rootNode.createChild('application/pkcs7-signature', { filename: 'smime.p7s' });
      signatureNode.setContent(derBuffer);

      // Switch in and return new root node
      mail.message = rootNode;
      callback();
    });
  };
}

function canonicalTransform(node) {
  if (node.getHeader('content-type').slice(0, 5) === 'text/' && typeof node.content === 'string') {
    node.content = node.content.replace(/\r\n|\r|\n/g, '\r\n');
  }
  node.childNodes.forEach(canonicalTransform);
}