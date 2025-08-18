import {
  Controller,
  Post,
  Body,
  Request,
  UseGuards,
  Get,
  Req,
  Res,
  HttpStatus,
} from '@nestjs/common';
import type { Response } from 'express';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CreateUserDto } from './auth.dto';
import { GoogleOauthGuard } from './guards/google-oauth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() dto: CreateUserDto) {
    return this.authService.register(dto);
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@Request() req) {
    return this.authService.logout(req.user.userId);
  }

  @Post('refresh')
  async refresh(@Body() dto: { userId: number; refreshToken: string }) {
    return this.authService.refresh(dto.userId, dto.refreshToken);
  }

  @Get('google')
  @UseGuards(GoogleOauthGuard)
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  async auth() {}

  @Get('google/callback')
  @UseGuards(GoogleOauthGuard)
  async googleAuthCallback(@Req() req, @Res() res: Response) {
    const result = await this.authService.loginWithGoogle(req.user);

    // If user was just registered, they won't have tokens yet
    let tokens;
    if ('accessToken' in result) {
      tokens = result;
    } else {
      // User was just registered, generate tokens
      tokens = await this.authService.login(result);
    }

    res.cookie('access_token', tokens.accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
    });
    return tokens.accessToken;
  }
}
