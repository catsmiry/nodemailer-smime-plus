const forge = require('node-forge');
const MimeNode = require('nodemailer/lib/mime-node/index.js');
const fs = require('fs');

module.exports = function (options) {
  return function (mail, callback) {
    // Load the .p12 file
    let p12Buffer;
    if (options.cert) {
      p12Buffer = fs.readFileSync(options.cert); // PKCS#12ファイルを読み込む
    } else {
      return callback(new Error('cert option is required.'));
    }

    // Decode the .p12 file using the provided passphrase
    const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString('binary'));
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, options.key); // options.key をパスフレーズとして使用

    // Extract the private key and certificate
    const bags = p12.getBags({ bagType: forge.pki.oids.keyBag });
    const keyBag = bags[forge.pki.oids.keyBag];
    const key = keyBag && keyBag.length > 0 ? keyBag[0].key : null;

    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const certBag = certBags[forge.pki.oids.certBag];
    const cert = certBag && certBag.length > 0 ? certBag[0].cert : null;

    if (!key) {
      return callback(new Error("Key not found in the P12 file."));
    }

    if (!cert) {
      return callback(new Error("Certificate not found in the P12 file."));
    }

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
      p7.addCertificate(cert);
      p7.addSigner({
        key: key,
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