import { config, isProd } from '@/config/app.config';
import mongoose from 'mongoose';

export const connectToDb = async () => {
  if (!isProd) mongoose.set('debug', true);
  await mongoose.connect(config.dbUrl);
};
