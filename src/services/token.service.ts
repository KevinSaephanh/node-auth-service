import { Response } from 'express';
import { sign, verify } from 'jsonwebtoken';
import { config, isProd } from '@/config/app.config';
import { Token, TokenType } from '@/utilts/jwt';

export class TokenService {
  private refreshTokenSecret: string;
  private refreshTokenExpiresIn: string;
  private accessTokenSecret: string;
  private accessTokenExpiresIn: string;

  constructor() {
    this.refreshTokenSecret = config.auth.refreshTokenSecret;
    this.refreshTokenExpiresIn = config.auth.refreshTokenExpiresIn;
    this.accessTokenSecret = config.auth.accessTokenSecret;
    this.accessTokenExpiresIn = config.auth.accessTokenExpiresIn;
  }

  signToken(id: string, tokenType: TokenType) {
    if (tokenType == 'access') {
      return sign(id, this.accessTokenSecret, {
        expiresIn: this.accessTokenExpiresIn,
      });
    }
    return sign(id, this.refreshTokenSecret, {
      expiresIn: this.refreshTokenExpiresIn,
    });
  }

  signTokens(userId: string, res: Response) {
    const accessToken = this.signToken(userId, 'access');
    const refreshToken = this.signToken(userId, 'refresh');
    this.setRefreshToken(refreshToken, res);
    return { accessToken, refreshToken };
  }

  setRefreshToken(token: string, res: Response) {
    res.cookie('refresh_token', token, {
      httpOnly: true,
      secure: isProd,
      path: '/',
    });
  }

  verifyToken(token: string, tokenType: TokenType) {
    let secret = '';
    if (tokenType == 'access') secret = this.accessTokenSecret;
    else secret = this.refreshTokenSecret;
    return verify(token, secret) as Token;
  }

  clearTokens(res: Response) {
    res.cookie('access_token', '', { maxAge: 1 });
    res.cookie('refresh_token', '', { maxAge: 1 });
  }
}
