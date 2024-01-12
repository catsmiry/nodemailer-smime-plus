# Nodemailer plugin to sign mail using S/MIME

This is an up-to-date version of the original [nodemailer-smime](https://github.com/gazoakley/nodemailer-smime)
package.

## Install

Install from npm

    npm install nodemailer-smime-plus --save

## Usage

Load the `nodemailer-smime-plus` plugin

```javascript
import smime from 'nodemailer-smime-plus';
```

Attach it as a 'stream' handler for a nodemailer transport object

```javascript
const options = {
  cert: '<PEM formatted cert>',
  chain: [
    '<PEM formatted cert>',
  ],
  key: '<PEM formatted key>',
};
transporter.use('stream', smime(options));
```

## Options

  * `cert` - PEM formatted SMIME certificate to sign/bundle mail with
  * `chain` - array of PEM formatted certificates to bundle
  * `key` - PEM formatted private key associated with certificate

## Example

```javascript
import nodemailer from 'nodemailer';
import smime from 'nodemailer-smime-plus';

const transporter = nodemailer.createTransport();
const options = {
  cert: '<PEM formatted cert>',
  chain: [
    '<PEM formatted cert>',
  ],
  key: '<PEM formatted key>',
};
transporter.use('stream', smime(options));
transporter.sendMail({
  from: 'me@example.com',
  to: 'receiver@example.com',
  html: '<b>Hello world!</b>'
});
```

## License

**MIT**
