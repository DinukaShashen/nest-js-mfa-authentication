import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true, nullable: false })
  email: string;

  @Column({ nullable: false })
  password: string; // hashed

  @Column({ nullable: true })
  twoFactorSecret?: string;

  @Column({ default: false })
  isTwoFactorEnabled: boolean;

  @Column({ default: false })
  isPending: boolean; // true if waiting for MFA verify

  @Column({ nullable: true })
  pendingCreatedAt?: Date; // timestamp for 5 min timeout

  @Column({ default: 0 })
  mfaFailCount: number; // count failed MFA attempts

  @Column({ nullable: true })
  mfaLockUntil?: Date; // timestamp when lock ends (5 min after 3 fails)

  @Column({ default: false })
  tempTokenUsed: boolean; // true after successful MFA verification to prevent reuse

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
