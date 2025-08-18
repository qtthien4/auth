import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './users.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(@InjectRepository(User) private repo: Repository<User>) {}

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
