const forge = require('node-forge');
const fs = require('fs').promises;
const MimeNode = require('nodemailer/lib/mime-node/index.js');

module.exports = function (options) {
  return async function (mail, callback) {
    try {
      // P12ファイルを読み込む
      const p12Buffer = await fs.readFile(options.cert, { encoding: null });
      const p12Asn1 = forge.asn1.fromDer(forge.util.createBuffer(p12Buffer));
      const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, options.key); // options.key はパスフレーズ

      // キーバッグと証明書バッグを取得
      const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
      const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });

      // キーバッグと証明書バッグから最初の要素を取得
      const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];
      const certBag = certBags[forge.pki.oids.certBag]?.[0];

      // キーバッグまたは証明書バッグが未定義または空の場合はエラーをスロー
      if (!keyBag || !certBag) {
        throw new Error("KeyBag or CertBag is undefined or empty in the P12 file.");
      }

      // キーを取得
      let key = keyBag.key;

      // Uint8Array 型の場合の変換処理
      if (key instanceof Uint8Array) {
        const derBuffer = forge.util.createBuffer(key);
        const asn1Key = forge.asn1.fromDer(derBuffer);
        key = forge.pki.privateKeyFromAsn1(asn1Key);
      }

      // キーが有効な型（stringまたはPrivateKey）でない場合はエラーをスロー
      if (typeof key !== 'string' && typeof key !== 'object') {
        throw new Error("Key is not a valid type (string or PrivateKey).");
      }

      // 証明書を取得
      const cert = certBag.cert;

      // Create new root node for the signed email
      const rootNode = new MimeNode('multipart/signed; protocol="application/pkcs7-signature"; micalg=sha256;');
      const contentNode = rootNode.appendChild(mail.message);

      // Build content node for digest generation
      contentNode.build((err, buf) => {
        if (err) {
          return callback(err);
        }

        // PKCS#7署名データを作成
        const p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(buf.toString('binary'));
        p7.addCertificate(cert);
        p7.addSigner({
          key: key,
          certificate: cert,
          digestAlgorithm: forge.pki.oids.sha256,
        });

        // 署名を実行
        p7.sign();

        // DER形式に変換
        const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
        const derBuffer = Buffer.from(der, 'binary');

        // Append signature node
        const signatureNode = rootNode.createChild('application/pkcs7-signature', { filename: 'smime.p7s' });
        signatureNode.setContent(derBuffer);

        // Switch in and return new root node
        mail.message = rootNode;
        callback();
      });
    } catch (error) {
      callback(new Error('Failed to process P 12 file: ' + error.message));
    }
  };
};