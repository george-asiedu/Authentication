import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { QueryFailedError, Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';
import { SignupDto } from './dto/signup.dto';
import { JwtPayload, SignInResponse } from 'src/model/auth.model';
import { VerifyAccountDto } from './dto/verifyAccount.dto';
import { LoginDto } from './dto/login.dto';
import { User } from 'src/entities/user.entity';
import { RefreshTokenDto } from './dto/refreshToken.dto';
import { SignupResponseDto } from './dto/signupResponse.dto';
import { constants } from '../utils/constants';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailerService: MailerService,
  ) {}

  async signup(
    user: SignupDto,
  ): Promise<{ user: SignupResponseDto; token: string }> {
    const existingUser = await this.usersRepository.findOne({
      where: [{ email: user.email || '' }, { phone: user.phone || '' }],
    });
    if (existingUser) {
      throw new ConflictException('Phone or Email is already in use');
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    user.password = await User.hashPassword(user.password);
    const newUser = this.usersRepository.create({ ...user, code });

    try {
      await this.usersRepository.save(newUser);

      const blockToken = this.jwtService.sign(
        { userId: newUser.id },
        {
          secret: this.configService.get<string>('JWT_SECRET'),
          expiresIn: constants.expiresIn,
        },
      );

      try {
        await this.mailerService.sendMail({
          to: newUser.email,
          subject: 'Your Two Factor Authentication Code',
          text: `Your 2FA code is: ${code}.`,
        });
      } catch (emailError) {
        throw new BadRequestException(
          `Error sending email: ${emailError.message}`,
        );
      }
      const { id, code: userCode, email, phone, dob, name, role } = newUser;

      return {
        user: { id, code: userCode, email, phone, dob, name, role },
        token: blockToken,
      };
    } catch (error) {
      if (
        error instanceof QueryFailedError &&
        error.driverError.code === '23505'
      ) {
        throw new ConflictException('Phone or Email is already in use');
      }
      throw error;
    }
  }

  async VerifyAccount(body: VerifyAccountDto, token: string) {
    let payload: JwtPayload;
    try {
      payload = this.jwtService.verify(token, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });
    } catch {
      throw new BadRequestException('Invalid or expired token');
    }

    if (!payload || !payload.userId) {
      throw new BadRequestException('Invalid token');
    }

    const userId = payload.userId;
    const user = await this.usersRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new BadRequestException('User not found');
    }
    if (user.code !== body.code) {
      throw new BadRequestException('Invalid 2FA code');
    }

    user.isVerified = true;
    user.code = null;
    await this.usersRepository.save(user);
  }

  async login(loginDto: LoginDto): Promise<SignInResponse> {
    const { phone, password, email } = loginDto;
    const user = await this.usersRepository.findOne({
      where: phone ? { phone } : { email },
      select: [
        'id',
        'email',
        'password',
        'name',
        'phone',
        'dob',
        'role',
        'isVerified',
      ],
    });

    if (!user) throw new BadRequestException('Invalid credentials');
    if (!user.isVerified) throw new BadRequestException('Account not verified');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) throw new BadRequestException('Invalid password');

    const jwtRefreshExpiry = this.configService.get<string>(
      'JWT_REFRESH_EXPIRES_IN',
    );
    const jwtRefreshSecret =
      this.configService.get<string>('JWT_REFRESH_SECRET');

    const payload = {
      id: user.id,
      email: user.email,
      name: user.name,
      phone: user.phone,
      sub: user.id,
    };
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: this.configService.get<string>('JWT_EXPIRY'),
      secret: this.configService.get<string>('JWT_SECRET'),
    });
    const refreshToken = this.jwtService.sign(payload, {
      secret: jwtRefreshSecret,
      expiresIn: jwtRefreshExpiry,
    });

    user.refreshToken = refreshToken;
    await this.usersRepository.save(user);

    return {
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        phone: user.phone,
        role: user.role,
        dob: user.dob,
      },
    };
  }

  async refreshToken(refreshToken: RefreshTokenDto) {
    try {
      const payload = this.jwtService.verify(refreshToken.refresh_token, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });

      const user = await this.usersRepository.findOne({
        where: { id: payload.sub, refreshToken: refreshToken.refresh_token },
      });

      if (!user) throw new BadRequestException('Invalid refresh token');

      const newAccessToken = this.jwtService.sign(
        {
          email: user.email,
          sub: user.id,
        },
        {
          secret: this.configService.get<string>('JWT_SECRET'),
          expiresIn: this.configService.get<string>('JWT_EXPIRY'),
        },
      );

      const newRefreshToken = this.jwtService.sign(
        {
          email: user.email,
          sub: user.id,
        },
        {
          secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
          expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES_IN'),
        },
      );

      user.refreshToken = newRefreshToken;
      await this.usersRepository.save(user);

      return { accessToken: newAccessToken, refreshToken: newRefreshToken };
    } catch {
      throw new BadRequestException('Invalid or expired refresh token');
    }
  }
}
