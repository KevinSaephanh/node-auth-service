import Joi from 'joi';

const passwordRegex = new RegExp('(?=.*d)(?=.*[a-z])(?=.*[A-Z]).*');

const customPasswordValidation = (
  value: string,
  customHelpers: Joi.CustomHelpers
) => {
  if (value.length < 8) {
    return customHelpers.message({
      custom: 'password must be at least 8 characters',
    });
  }

  if (value.length > 100) {
    return customHelpers.message({
      custom: 'password must be less than 100 characters long',
    });
  }

  if (!value.match(passwordRegex)) {
    return customHelpers.message({
      custom: 'password must contain at least 1 letter and 1 number',
    });
  }

  return value;
};

export const PasswordSchema = Joi.string()
  .required()
  .custom(customPasswordValidation)
  .options({ stripUnknown: true });

export const SignupSchema = Joi.object({
  username: Joi.string(),
  email: Joi.string().email(),
  password: PasswordSchema,
  confirmPassword: Joi.any()
    .equal(Joi.ref('password'))
    .required()
    .options({ messages: { 'any.only': 'Passwords do not match' } }),
})
  .options({ stripUnknown: true, presence: 'required' })
  .required();

export const LoginSchema = Joi.object({
  email: Joi.string().email(),
  password: Joi.string(),
})
  .options({ stripUnknown: true, presence: 'required' })
  .required();

export const OauthSchema = Joi.object({
  code: Joi.string(),
})
  .options({ stripUnknown: true, presence: 'required' })
  .required();
