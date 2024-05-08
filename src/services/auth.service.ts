import { Request, Response } from 'express';
import { ApiError } from '@/utilts/api-error';
import { TokenService } from './token.service';
import { LoginDto, SignupDto } from '@/dtos/auth.dto';
import { UserService } from './user.service';
import { compare } from 'bcrypt';
import axios from 'axios';
import { config } from '@/config/app.config';
import { OAuth2Client } from 'google-auth-library';
import { MailerService } from './mailer.service';
import { UserDocument } from '@/models/User';

export class AuthService {
  private readonly userService = new UserService();
  private readonly tokenService = new TokenService();
  private readonly mailerService = new MailerService();
  private googleClient: OAuth2Client;

  constructor() {
    this.googleClient = new OAuth2Client(
      config.auth.oauth.googleClientId,
      config.auth.oauth.googleClientSecret,
      'postmessage'
    );
  }

  async signup({ email, username, password, confirmPassword }: SignupDto) {
    if (password !== confirmPassword) {
      throw new ApiError(400, 'Passwords do not match');
    }

    const user = await this.userService.createUser({
      email,
      username,
      password,
    });

    // Create token and send email
    const accessToken = this.tokenService.signToken(user.id, 'access');
    await this.mailerService.sendVerificationEmail(
      user.email,
      user.username,
      accessToken
    );
  }

  async login({ email, password }: LoginDto, res: Response) {
    const user = await this.userService.findUserBy({ email, active: true });

    // User doesn't exist or is unverified
    if (!user) {
      throw new ApiError(404, 'User not found or unverified');
    }

    // Compare passwords is user exists
    if (!(await compare(password, user.password))) {
      throw new ApiError(404, 'Email and/or password is incorrect');
    }

    // Create tokens and set
    const { accessToken } = this.tokenService.signTokens(user.id, res);
    return { user, accessToken };
  }

  async googleOauthRedirect(code: string, res: Response) {
    const googleResponse = await this.googleClient.getToken(code);
    const idToken = googleResponse.tokens.id_token as string;
    const ticket = await this.googleClient.verifyIdToken({
      idToken,
      audience: config.auth.oauth.googleClientId,
    });
    const payload = ticket.getPayload();
    if (payload) {
      const { accessToken } = this.tokenService.signTokens(payload.sub, res);
      return { user: payload, accessToken };
    }
    return null;
  }

  async githubOauthRedirect(code: string, res: Response) {
    // Get github access token
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
    if (tokenResponse.status !== 200) {
      throw new ApiError(400, 'Error fetching access token from Github');
    }

    // Fetch user data with access token
    const userResponse = await axios.get('https://api.github.com/user', {
      headers: {
        Authorization: `${tokenResponse.data['access_token']} ${tokenResponse.data['token_type']}`,
      },
    });
    if (userResponse.status !== 200) {
      throw new ApiError(400, 'Error fetching user data from Github');
    }

    // Create JWTs
    const user = userResponse.data;
    const { accessToken } = this.tokenService.signTokens(user.id, res);
    return { user, accessToken };
  }

  async logout(res: Response) {
    this.tokenService.clearTokens(res);
  }

  async refresh(req: Request) {
    const refreshToken = req.cookies['refresh_token'];
    if (!refreshToken) {
      throw new ApiError(403, 'No refresh token provided');
    }
    const { userId } = this.tokenService.verifyToken(refreshToken, 'refresh');
    const user = await this.userService.findUserBy({ id: userId });
    const accessToken = this.tokenService.signToken(userId, 'access');
    return { user, accessToken };
  }

  async sendVerificationEmail(email: string) {
    const user = await this.userService.findUserBy({ email });
    const token = this.tokenService.signToken(user.id, 'access');
    await this.mailerService.sendVerificationEmail(email, user.username, token);
  }

  async verifyEmail(token: string, res: Response) {
    // Decode token to retrieve user id
    const decoded = this.tokenService.verifyToken(token, 'access');

    // Find and update user
    const user = await this.userService.findUserBy({ id: decoded.userId });
    user.active = true;
    await this.userService.updateUser(user);

    // Sign tokens and return with user
    const { accessToken } = this.tokenService.signTokens(user.id, res);
    return { user, accessToken };
  }

  async sendPasswordResetEmail(email: string) {
    const user = await this.userService.findUserBy({ email });
    const token = this.tokenService.signToken(user.id, 'access');
    await this.mailerService.sendPasswordResetEmail(
      email,
      user.username,
      token
    );
  }

  async updatePassword(token: string, password: string, res: Response) {
    // Verify token and update user password
    const { userId } = this.tokenService.verifyToken(token, 'access');
    const user = await this.userService.findUserBy({ id: userId });
    await this.userService.updateUser({ ...user, password } as UserDocument);

    // Sign tokens and return with user
    const { accessToken } = this.tokenService.signTokens(user.id, res);
    return { user, accessToken };
  }
}
