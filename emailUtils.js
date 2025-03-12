const nodemailer = require('nodemailer');

async function sendVerificationEmail(email, verificationUrl, verificationCode) {
  const transporter = nodemailer.createTransport({
    service: 'gmail', // Or another service
    auth: {
      user: process.env.EMAIL,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: 'ChatBot Email Verification Code',
    text: `Go to this link to verify your email: ${verificationUrl} \n Your verification code: ${verificationCode}`,
  };

  try {
    console.log('Sending verification email...');
    console.log('Email:', email);
    console.log('Verification URL:', verificationUrl);
    console.log('Verification Code:', verificationCode);

    const info = await transporter.sendMail(mailOptions);
    console.log('Verification email sent: %s', info.messageId);
    console.log('Verification code sent: %s', verificationCode);
  } catch (error) {
    console.error('Error sending verification email:', error.message);
    console.error('Error details:', error.stack);
  }
}

module.exports = { sendVerificationEmail };
