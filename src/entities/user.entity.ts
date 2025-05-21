import {
  Column,
  CreateDateColumn,
  DeleteDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import * as bcrypt from 'bcrypt';
import { UserRole } from 'src/model/role.enum';

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  public id!: string;

  @Column()
  public name!: string;

  @Column({ type: 'varchar', length: 15, nullable: true, unique: true })
  public phone!: string;

  @Column({ type: 'date', nullable: true })
  public dob!: string;

  @Column({ unique: true, nullable: true })
  public email!: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.User,
  })
  public role!: UserRole;

  @Column()
  public password!: string;

  @Column({ nullable: true })
  public refreshToken!: string;

  @Column({ type: 'varchar', nullable: true })
  code!: string | null;

  @Column({ default: false })
  isVerified!: boolean;

  @CreateDateColumn({ type: 'timestamp' })
  createdAt!: Date;

  @UpdateDateColumn({ type: 'timestamp' })
  updatedAt!: Date;

  @DeleteDateColumn({ type: 'timestamp', nullable: true })
  deletedAt!: Date | null;

  public static async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  }
}
