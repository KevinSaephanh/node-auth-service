import { AuthService } from '@/services/auth.service';
import { Request, Response } from 'express';

export class AuthController {
  private readonly authService = new AuthService();

  async signup(req: Request, res: Response) {
    await this.authService.signup(req.body, res);
    res.status(201).send({ message: 'Email has been sent' });
  }

  async login(req: Request, res: Response) {
    const accessToken = await this.authService.login(req.body, res);
    res.status(200).send({ accessToken });
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

  async updatePassword(req: Request, res: Response) {
    const updatedUser = await this.authService.updatePassword(
      req.params.token,
      req.body.password
    );
    res.status(200).send(updatedUser);
  }
}
