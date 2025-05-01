import {
  Body,
  Controller,
  Post,
  Query,
  UseGuards,
  UseInterceptors,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { TransformInterceptor } from '../interceptors/transform.interceptor';
import {
  BadRequestExample,
  LoginBadRequestExample,
  LoginResponseExample,
  UserResponseExample,
} from 'src/utils/response.model';
import { SignupDto } from './dto/signup.dto';
import { AuthService } from './auth.service';
import { VerifyAccountDto } from './dto/verifyAccount.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refreshToken.dto';
import { AuthGuard } from '../guard/auth/auth.guard';

@ApiTags('Authentication')
@Controller('auth')
@UseInterceptors(TransformInterceptor)
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  @ApiOperation({ summary: 'Creates a new user into the system.' })
  @ApiBody({
    type: SignupDto,
    description: 'JSON structure to create a new user.',
  })
  @ApiResponse({
    status: 201,
    description: 'Success',
    example: UserResponseExample,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: BadRequestExample,
  })
  async signup(@Body() user: SignupDto) {
    return await this.authService.signup(user);
  }

  @Post('verify-account')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  @ApiOperation({
    summary: "Verifies the 2FA code sent to the user's email using token.",
  })
  @ApiParam({
    name: 'token',
    description: 'The token for the user to verify their account.',
  })
  @ApiBody({
    type: VerifyAccountDto,
    description: "2FA code to verify a user's account",
  })
  @ApiResponse({
    status: 200,
    description: 'Success.',
    example: { message: 'Success' },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: { message: 'Invalid 2FA code or user not found.' },
  })
  async verifyAccount(
    @Query('token') token: string,
    @Body() verifyAccountDto: VerifyAccountDto,
  ) {
    return await this.authService.VerifyAccount(verifyAccountDto, token);
  }

  @Post('login')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  @ApiOperation({ summary: 'Sign in a user into the system.' })
  @ApiBody({
    type: LoginDto,
    description: 'JSON structure to login a user.',
  })
  @ApiResponse({
    status: 200,
    description: 'Success',
    example: LoginResponseExample,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request',
    example: LoginBadRequestExample,
  })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @Post('refresh-token')
  @UsePipes(new ValidationPipe({ forbidNonWhitelisted: true }))
  @ApiOperation({
    summary:
      'Allow continuous user access in the system using a refresh token.',
  })
  @ApiBody({ type: RefreshTokenDto, description: 'Refresh token string' })
  @ApiResponse({
    status: 200,
    description: 'Success',
    example: LoginResponseExample,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: { message: 'Invalid token.' },
  })
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenDto);
  }
}
