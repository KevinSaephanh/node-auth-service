import { ApiError } from '@/utilts/api-error';
import logger from '@/utilts/logger';
import { Request, Response, NextFunction } from 'express';

export const errorHandler = (
  err: ApiError,
  _req: Request,
  res: Response,
  _next: NextFunction
) => {
  logger.error(`Encountered error: ${err}`);
  if (err instanceof ApiError) {
    return res.status(err.statusCode).json(err.JSON);
  } else {
    return res.status(500).send('Internal Service Error');
  }
};
