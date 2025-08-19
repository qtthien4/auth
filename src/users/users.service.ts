import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole } from './users.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(@InjectRepository(User) private repo: Repository<User>) {
    this.ensureAdmin();
  }

  private async ensureAdmin() {
    const admin = await this.repo.findOne({ where: { email: 'admin' } });
    if (!admin) {
      const user = this.repo.create({
        email: 'admin',
        password: await bcrypt.hash('admin', 10),
        role: UserRole.ADMIN,
      });
      await this.repo.save(user);
    }
  }

  async setRole(userId: number, role: UserRole) {
    const result = await this.repo.update(userId, { role });
    if (result.affected === 0) {
      throw new Error('User not found');
    }
  }

  async create(email: string, password: string) {
    const hash = await bcrypt.hash(password || email, 10);
    const user = this.repo.create({ email, password: hash });
    return this.repo.save(user);
  }

  findByEmail(email: string) {
    return this.repo.findOne({ where: { email } });
  }

  findById(id: number) {
    return this.repo.findOne({ where: { id } });
  }

  async updateRefreshToken(userId: number, refreshToken: string | null) {
    const hash = refreshToken ? await bcrypt.hash(refreshToken, 10) : null;
    await this.repo.update(userId, { refreshToken: hash });
  }
}
