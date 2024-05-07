import { AuthService } from '@/services/auth.service';
import { Request, Response } from 'express';

export class AuthController {
  private readonly authService = new AuthService();

  async signup(req: Request, res: Response) {
    await this.authService.signup(req.body, res);
    res.status(201).send({ message: 'Verification email sent' });
  }

  async login(req: Request, res: Response) {
    const data = await this.authService.login(req.body, res);
    res.status(200).send(data);
  }

  async googleOauthRedirect(req: Request, res: Response) {
    const data = await this.authService.googleOauthRedirect(req.body.code, res);
    if (data) {
      res.status(200).send(data);
    } else {
      res.json(401).send({ message: 'Google oauth failed' });
    }
  }

  async githubOauthRedirect(req: Request, res: Response) {
    const data = await this.authService.githubOauthRedirect(req.body.code, res);
    if (data) {
      res.status(200).send(data);
    } else {
      res.json(401).send({ message: 'Github oauth failed' });
    }
  }

  async logout(_req: Request, res: Response) {
    await this.authService.logout(res);
    res.status(204).send();
  }

  async refreshToken(req: Request, res: Response) {
    const accessToken = await this.authService.refreshToken(req);
    res.status(200).send({ accessToken });
  }

  async sendVerificationEmail(req: Request, res: Response) {
    await this.authService.sendVerificationEmail(req.body);
    res.status(200).send();
  }

  async verifyEmail(req: Request, res: Response) {
    const data = await this.authService.verifyEmail(
      req.query['token'] as string,
      res
    );
    res.status(200).send(data);
  }

  async sendPasswordResetEmail(req: Request, res: Response) {
    await this.authService.sendPasswordResetEmail(req.body);
    res.status(200).send();
  }

  async updatePassword(req: Request, res: Response) {
    const updatedUser = await this.authService.updatePassword(
      req.params.token,
      req.body.password
    );
    res.status(200).send(updatedUser);
  }
}
