import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../users/entities/user.entity.js';
import * as bcrypt from 'bcrypt';
import { generateSecret, generateURI, verify, generate } from 'otplib';
import * as qrcode from 'qrcode';
import { RegisterDto } from './dto/register.dto.js';
import { LoginDto } from './dto/login.dto.js';
import { Verify2FADto } from './dto/verify-2fa.dto.js';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  // Store used temp tokens to prevent reuse
  private usedTempTokens: Set<string> = new Set();

  constructor(
    @InjectRepository(User)
    public usersRepository: Repository<User>,
    public jwtService: JwtService,
  ) {}

  // ── REGISTER ── (step 1: create pending user + generate MFA secret/QR)
  async startRegister(
    dto: RegisterDto,
  ): Promise<{ qrCodeUrl: string; secret: string; message: string }> {
    // Find any existing user with this email
    const existing = await this.usersRepository.findOne({
      where: { email: dto.email },
    });

    // Case 1: Email exists and is fully registered (not pending) → block
    if (existing && !existing.isPending) {
      throw new ConflictException('Email already registered');
    }

    // Case 2: Email exists but pending → check timeout
    if (existing && existing.isPending) {
      const timeElapsed = existing.pendingCreatedAt
        ? Date.now() - existing.pendingCreatedAt.getTime()
        : 0;

      if (timeElapsed > 5 * 60 * 1000) {
        // Expired → safe to delete and replace
        await this.usersRepository.delete(existing.id);
      } else {
        // Still active → block new attempt
        throw new ConflictException(
          'Pending registration in progress. Wait 5 minutes or complete MFA verification.',
        );
      }
    }

    // No active conflict → create new pending user
    const hashedPassword = await bcrypt.hash(dto.password, 12);
    const secret = generateSecret();

    const otpauth = generateURI({
      issuer: 'YourAppName',
      label: dto.email,
      secret,
    });

    const qrCodeUrl = await qrcode.toDataURL(otpauth);

    const user = this.usersRepository.create({
      email: dto.email,
      password: hashedPassword,
      twoFactorSecret: secret,
      isTwoFactorEnabled: false,
      isPending: true,
      pendingCreatedAt: new Date(),
      mfaFailCount: 0,
      mfaLockUntil: undefined,
    });

    await this.usersRepository.save(user);

    return {
      qrCodeUrl,
      secret,
      message:
        'Scan QR with Google/Microsoft Authenticator. Then call /auth/verify-register with code.',
    };
  }

  // ── VERIFY REGISTER MFA ── (step 2: complete register)
  async verifyRegister(
    dto: Verify2FADto,
    email: string,
  ): Promise<{ message: string }> {
    const user = await this.usersRepository.findOne({ where: { email } });

    if (!user || !user.isPending) {
      throw new BadRequestException('No pending registration for this email');
    }

    if (!user.twoFactorSecret) {
      throw new BadRequestException('MFA not initialized');
    }

    // Check 5 min timeout
    if (
      user.pendingCreatedAt &&
      Date.now() - user.pendingCreatedAt.getTime() > 5 * 60 * 1000
    ) {
      await this.usersRepository.delete(user.id);
      throw new BadRequestException(
        'Registration timeout (5 min). Please register again.',
      );
    }

    try {
      // In v13, verify returns a VerifyResult object
      const result = await verify({
        token: dto.token,
        secret: user.twoFactorSecret,
      });

      // Check if the result indicates a valid token
      // You need to check the actual structure of VerifyResult
      // Based on the error, it seems we need to access a property
      if (!result || !result.valid) {
        throw new UnauthorizedException('Invalid MFA code');
      }
    } catch (error) {
      this.logger.error(`Verification error: ${error.message}`);
      throw new UnauthorizedException('Invalid MFA code');
    }

    user.isTwoFactorEnabled = true;
    user.isPending = false;
    user.pendingCreatedAt = undefined;
    await this.usersRepository.save(user);

    return {
      message: 'Registration completed successfully. You can now login.',
    };
  }

  // ── LOGIN ── (step 1: password check → return MFA challenge if enabled)
  async startLogin(
    dto: LoginDto,
  ): Promise<{ requiresMFA: boolean; tempToken?: string; message: string }> {
    const user = await this.usersRepository.findOne({
      where: { email: dto.email },
    });

    if (!user || user.isPending) {
      throw new UnauthorizedException(
        'Invalid credentials or incomplete registration',
      );
    }

    const isPasswordValid = await bcrypt.compare(dto.password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isTwoFactorEnabled) {
      return { requiresMFA: false, message: 'Login successful (no MFA)' };
    }

    // Check if user is locked out
    if (user.mfaLockUntil && user.mfaLockUntil > new Date()) {
      const waitTime = Math.ceil(
        (user.mfaLockUntil.getTime() - Date.now()) / 1000 / 60,
      );
      throw new UnauthorizedException(
        `Account locked due to too many failed attempts. Try again in ${waitTime} minutes.`,
      );
    }

    // Create temp token (valid 5 min) for MFA step with unique ID to prevent reuse
    const tempToken = this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        temp: true,
        jti: `${user.id}-${Date.now()}-${Math.random().toString(36).substring(7)}`,
      },
      {
        expiresIn: '5m',
      },
    );

    return {
      requiresMFA: true,
      tempToken,
      message: 'Enter MFA code from authenticator app',
    };
  }

  // ── VERIFY LOGIN MFA ── (step 2: complete login → give real tokens)
  async verifyLogin(
    dto: Verify2FADto,
    tempToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    if (!tempToken) {
      throw new UnauthorizedException('Temp token is required');
    }

    // Check if token has been used before
    if (this.usedTempTokens.has(tempToken)) {
      throw new UnauthorizedException('This temp token has already been used');
    }

    let payload: any;
    try {
      payload = this.jwtService.verify(tempToken);
    } catch (err) {
      throw new UnauthorizedException('Invalid or expired temp token');
    }

    // Ensure it's a real temp token (has temp: true claim)
    if (!payload.temp || !payload.sub) {
      throw new UnauthorizedException('Invalid token type');
    }

    const userId = payload.sub;

    const user = await this.usersRepository.findOne({ where: { id: userId } });

    if (!user || !user.isTwoFactorEnabled) {
      throw new UnauthorizedException('MFA not enabled or invalid session');
    }

    if (!user.twoFactorSecret) {
      throw new UnauthorizedException('MFA secret not found');
    }

    // Check lock (from previous fails)
    if (user.mfaLockUntil && user.mfaLockUntil > new Date()) {
      throw new UnauthorizedException(
        'Account locked due to too many failed attempts. Try again later.',
      );
    }

    let isValid = false;

    try {
      // In v13, verify returns a VerifyResult object
      const result = await verify({
        token: dto.token,
        secret: user.twoFactorSecret,
      });

      // Check if the result indicates a valid token
      // You need to check the actual structure of VerifyResult
      isValid = result && result.valid === true;

      this.logger.debug(`Verification result: ${JSON.stringify(result)}`);
    } catch (error) {
      this.logger.error(`Verification error: ${error.message}`);
      isValid = false;
    }

    if (!isValid) {
      // Increment fail count
      user.mfaFailCount = (user.mfaFailCount || 0) + 1;

      if (user.mfaFailCount >= 3) {
        user.mfaLockUntil = new Date(Date.now() + 5 * 60 * 1000);
        user.mfaFailCount = 0;
      }

      await this.usersRepository.save(user);
      throw new UnauthorizedException('Invalid MFA code');
    }

    // Success → reset fails and lock
    user.mfaFailCount = 0;
    user.mfaLockUntil = undefined;
    await this.usersRepository.save(user);

    // Mark temp token as used to prevent reuse
    this.usedTempTokens.add(tempToken);

    const realPayload = { sub: user.id, email: user.email };

    const accessToken = this.jwtService.sign(realPayload, { expiresIn: '15m' });
    const refreshToken = this.jwtService.sign(realPayload, { expiresIn: '7d' });

    return { accessToken, refreshToken };
  }

  async register(dto: RegisterDto) {
    return this.startRegister(dto);
  }

  async login(dto: LoginDto) {
    return this.startLogin(dto);
  }
}
