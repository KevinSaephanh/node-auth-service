import { AuthController } from '@/controllers/auth.controller';
import { asyncWrap } from '@/middleware/async-wrap';
import { isAuth } from '@/middleware/is-auth';
import { limiter } from '@/middleware/rate-limit';
import { validateRequest } from '@/middleware/validate-request';
import {
  SignupSchema,
  LoginSchema,
  OauthSchema,
} from '@/validators/auth.validator';
import { Router } from 'express';

const router = Router();
const authController = new AuthController();

router.post(
  '/signup',
  limiter,
  validateRequest(SignupSchema),
  asyncWrap(authController.signup)
);
router.post(
  '/login',
  validateRequest(LoginSchema),
  asyncWrap(authController.login)
);
router.post(
  '/google/oauth/redirect',
  validateRequest(OauthSchema),
  asyncWrap(authController.googleOauthRedirect)
);
router.post(
  '/github/oauth/redirect',
  validateRequest(OauthSchema),
  asyncWrap(authController.githubOauthRedirect)
);
router.post('/logout', isAuth, asyncWrap(authController.logout));
router.post('/refresh-token', asyncWrap(authController.refreshToken));
router.patch(
  '/user/update-password',
  isAuth,
  asyncWrap(authController.updatePassword)
);

export default router;