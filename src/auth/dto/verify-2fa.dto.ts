import { IsString, Length, IsOptional, IsEmail } from 'class-validator';

export class Verify2FADto {
  @IsString()
  @Length(6, 6, { message: 'MFA code must be exactly 6 digits' })
  token: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  tempToken?: string;
}
