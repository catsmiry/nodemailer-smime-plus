declare module '@miry/nodemailer-smime-plus' {
  import forge from 'node-forge';
  import { PluginFunction } from 'nodemailer/lib/mailer';

  interface SmimeOptions {
    cert: string; // PKCS#12ファイルのパス
    key: string;  // PKCS#12ファイルのパスフレーズ
  }

  function smime(options: SmimeOptions): PluginFunction;

  export = smime;
}