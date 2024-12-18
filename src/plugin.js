const forge = require('node-forge');
const MimeNode = require('nodemailer/lib/mime-node/index.js');
const fs = require('fs');

module.exports = function (options) {
  return function (mail, callback) {
    // P12ファイルを読み込む
    let p12Buffer;
    if (options.cert) {
      p12Buffer = fs.readFileSync(options.cert); // P12ファイルを読み込む
    } else {
      return callback(new Error('cert option is required.'));
    }

    try {
      // P12ファイルをDER形式からASN.1形式に変換して解析
      const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
      const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, options.key); // options.key をパスフレーズとして使用

      // 証明書と秘密鍵を取得
      const bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
      const keyBag = bags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
      const privateKey = keyBag.key;
      const certBag = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag][0];
      const certificate = certBag.cert;

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
      canonicalTransform(contentNode);

      // Build content node for digest generation
      contentNode.build((err, buf) => {
        if (err) {
          return callback(err);
        }

        // Generate PKCS7 ASN.1
        const p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(buf.toString('binary'));
        p7.addCertificate(certificate);
        p7.addSigner({
          key: privateKey,
          certificate: certificate,
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
    } catch (error) {
      callback(error);
    }
  };
}

function canonicalTransform(node) {
  if (node.getHeader('content-type').slice(0, 5) === 'text/' && typeof node.content === 'string') {
    node.content = node.content.replace(/\r\n|\r|\n/g, '\r\n');
  }
  node.childNodes.forEach(canonicalTransform);
}