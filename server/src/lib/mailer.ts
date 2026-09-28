/**
 * Mail transport abstraction. The console transport is for development only —
 * swap in an SMTP / provider implementation (SES, Postmark, …) for production.
 */
export interface Mail {
  to: string;
  subject: string;
  text: string;
}

export interface Mailer {
  send(mail: Mail): Promise<void>;
}

class ConsoleMailer implements Mailer {
  readonly outbox: Mail[] = []; // inspected by tests

  async send(mail: Mail): Promise<void> {
    this.outbox.push(mail);
    if (process.env.NODE_ENV !== 'test') {
      console.log(`\n📧  To: ${mail.to}\n    Subject: ${mail.subject}\n    ${mail.text.replaceAll('\n', '\n    ')}\n`);
    }
  }
}

export const mailer = new ConsoleMailer();
