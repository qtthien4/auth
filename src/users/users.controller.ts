import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { Roles } from '../auth/roles.decorator';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { UserRole } from './users.entity';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Get('me')
  @UseGuards(JwtAuthGuard)
  getProfile() {
    return { message: 'This is your profile' };
  }

  @Get('admin')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  getAdminData() {
    return { message: 'Only admin can see this' };
  }

  @Post('setRole')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  async setRole(@Body() dto: { userId: number; role: UserRole }) {
    await this.usersService.setRole(dto.userId, dto.role);
    return 'Success';
  }
}
