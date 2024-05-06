import { ApiError } from '@/utilts/api-error';
import { Request, Response, NextFunction } from 'express';

export const errorHandler = (
  err: ApiError,
  _req: Request,
  res: Response,
  _next: NextFunction
) => {
  if (err instanceof ApiError) {
    return res.status(err.statusCode).json(err.JSON);
  } else {
    return res.status(500).send('Internal Service Error');
  }
};
