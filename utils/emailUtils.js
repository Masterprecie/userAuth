const nodemailer = require("nodemailer");

const tp = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD,
  },
});

async function sendEmail(to, subject, body) {
  await tp.sendMail({
    from: "ikpaprecious2@gmail.com",
    to,
    subject,
    html: body,
  });
}

module.exports = sendEmail;
