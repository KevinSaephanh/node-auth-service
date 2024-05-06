import { Request, Response, NextFunction } from "express";
import { Schema } from "joi";

export const validateRequest =
  (schema: Schema) => async (req: Request, _res: Response, next: NextFunction) => {
    try {
      req.body = await schema.validateAsync(req.body);
      next();
    } catch (err) {
      next(err);
    }
  };
