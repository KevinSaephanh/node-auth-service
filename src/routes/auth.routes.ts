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
router.post('/refresh', asyncWrap(authController.refresh));
router.post(
  '/send-verification-email',
  asyncWrap(authController.sendVerificationEmail)
);
router.post('/verify-email', asyncWrap(authController.verifyEmail));
router.patch(
  '/send-password-reset-email',
  asyncWrap(authController.sendPasswordResetEmail)
);
router.patch('/user/update-password', asyncWrap(authController.updatePassword));

export default router;
