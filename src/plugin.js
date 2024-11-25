const forge = require('node-forge');
const MimeNode = require('nodemailer/lib/mime-node/index.js');
const fs = require('fs');

module.exports = function (options) {
  return async function (mail, callback) {
    // P12ファイルを読み込む
    let p12Buffer;
    if (options.cert) {
      p12Buffer = fs.readFileSync(options.cert); // PKCS#12ファイルを読み込む
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

      // メールメッセージを署名
      const contentNode = mail.message; // メールの内容を取得

      // 宛先が設定されているか確認
      if (!mail.data.to || mail.data.to.length === 0) {
        return callback(new Error('No recipients defined Error'));
      }

      // メールの内容を構築
      contentNode.build((err, buf) => {
        if (err) {
          return callback(err);
        }

        // S/MIME署名を作成
        const p7Signer = forge.pkcs7.createSignedData();
        p7Signer.content = forge.util.createBuffer(buf.toString('binary'));
        p7Signer.addCertificate(certificate);
        p7Signer.addSigner({
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
        p7Signer.sign();

        // S/MIME署名をDER形式でエンコード
        const asn1 = p7Signer.toAsn1(); // ASN.1形式に変換
        const signedDataDer = forge.asn1.toDer(asn1); // DER形式に変換
        const derBuffer = Buffer.from(signedDataDer.getBytes(), 'binary');

        // 署名ノードを追加
        const signatureNode = new MimeNode('application/pkcs7-signature', { filename: 'smime.p7s' });
        signatureNode.setContent(derBuffer);

        // ルートノードに署名ノードを追加
        const rootNode = new MimeNode('multipart/signed; protocol="application/pkcs7-signature"; micalg=sha256;');
        rootNode.appendChild(contentNode);
        rootNode.appendChild(signatureNode);

        // 新しいメールメッセージを設定
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