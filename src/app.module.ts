import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './users/entities/user.entity.js'; // ← NEW: import the entity
import { AuthModule } from './auth/auth.module.js';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),

    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres' as const,
        host: configService.get<string>('DATABASE_HOST') ?? 'localhost',
        port: configService.get<number>('DATABASE_PORT') ?? 5432,
        username: configService.get<string>('DATABASE_USER') ?? 'postgres',
        password: configService.get<string>('DATABASE_PASSWORD') ?? 'admin',
        database: configService.get<string>('DATABASE_NAME') ?? 'nest_auth_dev',
        entities: [User], // ← NEW: register the User entity here
        synchronize: true, // auto-create tables (dev only)
        logging: true, // see SQL queries in console
      }),
    }),

    AuthModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
