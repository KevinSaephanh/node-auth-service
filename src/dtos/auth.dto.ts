import { UserDocument } from '@/models/User';

export interface SignupDto {
  username: string;
  email: string;
  password: string;
  confirmPassword: string;
}

export interface LoginDto extends Pick<SignupDto, 'email' | 'password'> {}

export interface UpdatePasswordDto {
  oldPassword: string;
  newPassword: string;
  confirmNewPassword: string;
}

export type PartialUserRecord<K extends keyof UserDocument, T> = Partial<
  Record<K, T>
>;
