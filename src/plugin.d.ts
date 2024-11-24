declare module 'nodemailer-smime-plus' {
  import forge from 'node-forge';
  import { PluginFunction } from 'nodemailer/lib/mailer';

  interface SmimeOptions {
    cert: forge.pki.Certificate | string; // 文字列の場合はファイルパス
    chain: (forge.pki.Certificate | string)[]; // 文字列の場合はファイルパスの配列
    key: forge.pki.rsa.PrivateKey;
  }

  function smime(options: SmimeOptions): PluginFunction;

  export = smime;
}