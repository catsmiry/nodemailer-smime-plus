# Nodemailer plugin to sign mail using S/MIME

This is an up-to-date version of the original [nodemailer-smime](https://github.com/catsmiry/nodemailer-smime)
package.

## Install

Install from npm

    npm install @miry/nodemailer-smime-plus --save

## Usage

Load the `nodemailer-smime-plus` plugin

```javascript
import smime from 'nodemailer-smime-plus';
```

Attach it as a 'stream' handler for a nodemailer transport object

```javascript
const options = {
  cert: '/path/to/your/certificate.p12', // Path to the PKCS#12 file
  key: 'your_password', // Passphrase for the PKCS#12 file
};

// Use the S/MIME plugin
transporter.use('stream', smime(options));
```

## Options

* `cert` - Path to the PKCS#12 file containing the SMIME certificate used to sign/bundle the mail
* `key` - Passphrase for the PKCS#12 file

## Example

```javascript
import nodemailer from 'nodemailer';
import smime from '@miry/nodemailer-smime-plus';

const transporter = nodemailer.createTransport();

const options = {
  cert: '/path/to/your/certificate.p12', // Path to the PKCS#12 file
  key: 'your_password', // Passphrase for the PKCS#12 file
};

// Use the S/MIME plugin
transporter.use('stream', smime(options));

transporter.sendMail({
  from: 'me@example.com',
  to: 'receiver@example.com',
  html: '<b>Hello world!</b>'
}, (error, info) => {
  if (error) {
    return console.error('Error sending email:', error);
  }
  console.log('Email sent:', info.response);
});
```

## License

**MIT**
