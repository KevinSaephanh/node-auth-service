import mongoose from 'mongoose';
import { hash } from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { config } from '@/config/app.config';

export enum Role {
  Basic = 'Basic',
  Admin = 'Admin',
}

export type UserDocument = mongoose.Document & {
  username: string;
  email: string;
  password: string;
  avatar: string;
  role: Role;
};

const userSchema = new mongoose.Schema<UserDocument>(
  {
    _id: { type: String, default: () => uuidv4() },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: String,
    role: { type: String, enum: Role, default: Role.Basic },
  },
  { timestamps: true }
);

// Password has middleware
userSchema.pre('save', async function save(next) {
  const user = this as UserDocument;

  // Password has not been changed
  if (!user.isModified('password')) {
    return next();
  }

  hash(user.password, config.auth.salt);
  next();
});

export const User = mongoose.model<UserDocument>('User', userSchema);
