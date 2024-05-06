import { User, UserDocument } from '@/models/User';
import { ApiError } from '@/utilts/api-error';

export class UserService {
  async createUser(data: Partial<UserDocument>) {
    try {
      const user = await User.create(data);
      return user;
    } catch (err) {
      throw new ApiError(400, 'Error creating user');
    }
  }

  async findByProp(name: keyof UserDocument, value: any) {
    const user = await User.findOne({ [name]: value });
    if (!user) {
      throw new ApiError(404, 'User not found');
    }
    return user;
  }

  async updateUser(user: UserDocument) {
    return User.updateOne({ id: user.id }, user);
  }

  async deleteUser(userId: string) {
    return User.deleteOne({ id: userId });
  }
}
