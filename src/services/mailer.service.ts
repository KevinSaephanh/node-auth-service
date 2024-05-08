import SMTPTransport from 'nodemailer/lib/smtp-transport';
import { createTransport, Transporter } from 'nodemailer';
import logger from '@/utilts/logger';
import { config } from '@/config/app.config';

export interface SendEmailParams {
  from?: string;
  to: string | Array<string>;
  subject: string;
  html: string;
}

export class MailerService {
  private mailer: Transporter<SMTPTransport.SentMessageInfo>;
  private baseUrl: string;

  constructor() {
    this.mailer = createTransport({ url: config.email.smtp });
    this.baseUrl = config.web;
  }

  async sendVerificationEmail(
    to: string | string[],
    name: string,
    token: string
  ) {
    await this.sendEmail({
      to,
      subject: 'Email Verification',
      html: `Hello ${name},
      <br /><br />
      <span>Thank you for registering. Please confirm your account by clicking the link below.</span>
      <a clicktracking="off" href='${this.baseUrl}/auth/verify?token=${token}'>
        Confirm my email
      </a>
      <span>NOTE: this link is valid for 24 hours</span>
      <br /><br />
      <span>Thanks,</span>
      <br />
      <span>ImageGen</span>`,
    });
  }

  async sendPasswordResetEmail(email: string, username: string, token: string) {
    await this.sendEmail({
      to: email,
      subject: 'Reset Your Password',
      html: `<span> Hello ${username},</span>
      <br /> <br/>
      <span>Please reset your password with this 
        <a clicktracking="off" href='${this.baseUrl}/auth/set-password?token=${token}'>link</a>
      </span>
      <span>NOTE: this link is valid for 24 hours</span>
      <br /> <br/>
      <span>Thanks,</span>
      <br />
      <span>ImageGen</span>`,
    });
  }

  private async sendEmail({
    from = config.email.from,
    ...message
  }: SendEmailParams) {
    await this.mailer.sendMail({ from, ...message });
    logger.info('Email sent');
  }
}
