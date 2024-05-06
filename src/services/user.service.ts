import { User, UserDocument } from '@/models/User';
import { ApiError } from '@/utilts/api-error';
import logger from '@/utilts/logger';

export class UserService {
  async createUser(data: Partial<UserDocument>) {
    try {
      const user = await User.create(data);
      logger.info(`User created with id: ${user.id}`);
      return user;
    } catch (err) {
      logger.error(err);
      throw new ApiError(400, 'Error creating user');
    }
  }

  async findByProp(name: keyof UserDocument, value: any) {
    const user = await User.findOne({ [name]: value });
    if (!user) {
      logger.error(`User with ${name} ${value} not found`);
      throw new ApiError(404, 'User not found');
    }
    logger.info(`User with ${name} ${value} found`);
    return user;
  }

  async updateUser(user: UserDocument) {
    return User.updateOne({ id: user.id }, user);
  }

  async deleteUser(userId: string) {
    return User.deleteOne({ id: userId });
  }
}
