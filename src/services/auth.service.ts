import { Request, Response } from 'express';
import { ApiError } from '@/utilts/api-error';
import { TokenService } from './token.service';
import { LoginDto, SignupDto } from '@/dtos/auth.dto';
import { UserService } from './user.service';
import { compare } from 'bcrypt';
import axios from 'axios';
import { config } from '@/config/app.config';
import { OAuth2Client } from 'google-auth-library';

export class AuthService {
  private readonly userService = new UserService();
  private readonly tokenService = new TokenService();
  private googleClient: OAuth2Client;

  constructor() {
    this.googleClient = new OAuth2Client(
      config.auth.oauth.googleClientId,
      config.auth.oauth.googleClientSecret,
      'postmessage'
    );
  }

  async signup(
    { email, username, password, confirmPassword }: SignupDto,
    res: Response
  ) {
    if (password !== confirmPassword) {
      throw new ApiError(400, 'Passwords do not match');
    }

    const user = await this.userService.createUser({
      email,
      username,
      password,
    });

    // Create tokens and set
    const { accessToken } = this.tokenService.signTokens(user.id, res);
    return accessToken;
  }

  async login({ email, password }: LoginDto, res: Response) {
    const user = await this.userService.findByProp('email', email);

    // Compare passwords is user exists
    if (!(await compare(password, user.password))) {
      throw new ApiError(404, 'Username and/or password is incorrect');
    }

    // Create tokens and set
    const { accessToken } = this.tokenService.signTokens(user.id, res);
    return accessToken;
  }

  async googleOauthRedirect(code: string) {
    const res = await this.googleClient.getToken(code);
    const idToken = res.tokens.id_token as string;
    const ticket = await this.googleClient.verifyIdToken({
      idToken,
      audience: config.auth.oauth.googleClientId,
    });
    return ticket.getPayload();
  }

  async githubOauthRedirect(code: string) {
    const tokenResponse = await axios.post(
      'https://github.com/login/oauth/access_token',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          client_id: config.auth.oauth.githubClientId,
          client_secret: config.auth.oauth.githubClientSecret,
          code,
        }),
      }
    );
    return {
      user: tokenResponse.data.user,
      accessToken: tokenResponse.data.access_token,
    };
  }

  async logout(res: Response) {
    this.tokenService.clearTokens(res);
  }

  async refreshToken(req: Request) {
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) {
      throw new ApiError(403, 'No refresh token provided');
    }
    const { userId } = this.tokenService.verifyToken(refreshToken, 'refresh');
    return this.tokenService.signToken(userId, 'access');
  }

  async updatePassword(
    userId: string,
    { oldPassword, newPassword, confirmNewPassword }: any
  ) {
    const user = await this.userService.findByProp('id', userId);

    // Check old password matches current password
    if (!user || !(await compare(oldPassword, user.password))) {
      throw new ApiError(400, 'Password is incorrect');
    }

    // Check new password matches confirm password
    if (newPassword !== confirmNewPassword) {
      throw new ApiError(404, 'New password does not match.');
    }

    user.password = newPassword;
    return this.userService.updateUser(user);
  }
}
