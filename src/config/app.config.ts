const getEnvVar = (name: string) => {
  return process.env[name.toUpperCase()]!;
};

export const isProd = getEnvVar('NODE_ENV') === 'production';

export const config = {
  port: +getEnvVar('PORT'),
  web: isProd ? getEnvVar('WEB_URL') : 'http://localhost:3000',
  env: isProd ? 'production' : 'development',
  auth: {
    accessTokenSecret: getEnvVar('ACCESS_TOKEN_SECRET'),
    accessTokenExpiresIn: getEnvVar('ACCESS_TOKEN_EXPIRES_IN'),
    refreshTokenSecret: getEnvVar('REFRESH_TOKEN_SECRET'),
    refreshTokenExpiresIn: getEnvVar('REFRESH_TOKEN_EXPIRES_IN'),
    salt: getEnvVar('SALT'),
    oauth: {
      githubClientId: getEnvVar('GITHUB_CLIENT_ID'),
      githubClientSecret: getEnvVar('GITHUB_CLIENT_SECRET'),
      googleClientId: getEnvVar('GOOGLE_CLIENT_ID'),
      googleClientSecret: getEnvVar('GOOGLE_CLIENT_SECRET'),
    },
  },
  dbUrl: getEnvVar('MONGODB_URI'),
};
