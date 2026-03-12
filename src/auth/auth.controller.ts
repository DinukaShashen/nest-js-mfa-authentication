import {
  Controller,
  Post,
  Body,
  UsePipes,
  ValidationPipe,
  UnauthorizedException,
  BadRequestException,
  Get,
  UseGuards,
  Request,
} from '@nestjs/common';
import { AuthService } from './auth.service.js';
import { JwtAuthGuard } from '../common/gurds/jwt-auth.guard.js';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // REGISTER STEP 1: Start + get MFA QR
  @Post('register')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  async register(@Body() dto: RegisterDto) {
    return this.authService.startRegister(dto);
  }

  // REGISTER STEP 2: Verify MFA to complete
  @Post('verify-register')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  async verifyRegister(@Body() body: { token: string; email: string }) {
    const { token, email } = body;
    if (!token || !email) {
      throw new UnauthorizedException('token and email are required');
    }
    return this.authService.verifyRegister({ token }, email);
  }

  // LOGIN STEP 1: Password + MFA challenge
  @Post('login')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  async login(@Body() dto: LoginDto) {
    return this.authService.startLogin(dto);
  }

  // LOGIN STEP 2: Verify MFA with tempToken (secure)
  @Post('verify-login')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  async verifyLogin(@Body() body: { token: string; tempToken: string }) {
    const { token, tempToken } = body;
    if (!token || !tempToken) {
      throw new BadRequestException('token and tempToken are required');
    }
    return this.authService.verifyLogin({ token }, tempToken);
  }

  // REFRESH ACCESS TOKEN
  @Post('refresh')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  async refresh(@Body('refreshToken') refreshToken: string) {
    if (!refreshToken) {
      throw new BadRequestException('refreshToken is required');
    }

    let payload: any;
    try {
      payload = this.authService.jwtService.verify(refreshToken);
    } catch (err) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Optional: check if user still exists and MFA enabled
    const user = await this.authService.usersRepository.findOne({
      where: { id: payload.sub },
    });
    if (!user || !user.isTwoFactorEnabled) {
      throw new UnauthorizedException('Invalid session');
    }

    const newAccessToken = this.authService.jwtService.sign(
      { sub: user.id, email: user.email },
      { expiresIn: '15m' },
    );

    return { accessToken: newAccessToken };
  }

  // PROFILE ENDPOINT
  @Get('profile')
  @UseGuards(JwtAuthGuard)
  getProfile(@Request() req) {
    return req.user; // { userId, email }
  }
}
