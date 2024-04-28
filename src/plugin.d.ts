declare module 'nodemailer-smime-plus' {
  import forge from 'node-forge';
  import { PluginFunction } from 'nodemailer/lib/mailer';

  interface SmimeOptions {
    cert: forge.pki.Certificate;
    chain: forge.pki.Certificate[];
    key: forge.pki.rsa.PrivateKey;
  }

  function smime(options: SmimeOptions): PluginFunction;

  export = smime;
}
