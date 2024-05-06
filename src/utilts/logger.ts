import { isProd } from '@/config/app.config';
import winston from 'winston';

const options: winston.LoggerOptions = {
  transports: [
    new winston.transports.Console({
      level: isProd ? 'error' : 'debug',
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        winston.format.printf(
          (info) => `${info.timestamp} ${info.level}: ${info.message}`
        )
      ),
    }),
    new winston.transports.File({
      filename: 'debug.log',
      level: 'debug',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
    }),
  ],
};
const logger = winston.createLogger(options);

if (!isProd) {
  logger.debug('Logging initialized at debug level');
}

export default logger;
