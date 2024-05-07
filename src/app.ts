import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.routes';
import { errorHandler } from './middleware/error-handler';
import { config } from './config/app.config';
import { connectToDb } from './database/db';

const main = async () => {
  const port = config.port;
  const app = express();

  app.set('port', port);
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Routes
  app.use('/api/v1/auth', authRoutes);

  // Middlewares
  app.use(errorHandler);
  app.use(helmet());
  app.use(cookieParser());

  // Mongoose
  await connectToDb();

  app.listen(app.get('port'), () => {
    console.log('App running on port ', port);
  });
};

main();
