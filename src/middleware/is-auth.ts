import { Request, Response } from 'express';
import { verify, JwtPayload } from 'jsonwebtoken';
import { asyncWrap } from './async-wrap';
import { ApiError } from '@/utilts/api-error';
import { config } from '@/config/app.config';
import { UserDocument } from '@/models/User';

export interface UserRequest extends Request {
  user: UserDocument;
}

export const isAuth = asyncWrap(async (req: Request, _res: Response) => {
  const token = req.headers['authorization']?.split(' ')?.[1];

  if (!token) {
    throw new ApiError(403, 'No token provided!');
  }

  try {
    const { user } = verify(token, config.auth.accessTokenSecret) as JwtPayload;
    (req as UserRequest).user = user;
  } catch (err) {
    throw new ApiError(401, 'Unauthorized');
  }
});
