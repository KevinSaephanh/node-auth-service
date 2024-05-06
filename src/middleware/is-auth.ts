import { Request, Response } from 'express';
import { verify, JwtPayload } from 'jsonwebtoken';
import { asyncWrap } from './async-wrap';
import { ApiError } from '@/utilts/api-error';
import { config } from '@/config/app.config';
import logger from '@/utilts/logger';

export const isAuth = asyncWrap(async (req: Request, _res: Response) => {
  const token = req.headers['authorization']?.split(' ')?.[1];

  if (!token) {
    throw new ApiError(403, 'No token provided!');
  }

  try {
    const { user } = verify(token, config.auth.accessTokenSecret) as JwtPayload;
    req.user = user;
  } catch (err) {
    logger.error(`Token ${token} is invalid`);
    throw new ApiError(401, 'Unauthorized');
  }
});
