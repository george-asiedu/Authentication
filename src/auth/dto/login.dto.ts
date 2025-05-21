import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Length,
  MinLength,
} from 'class-validator';

export class LoginDto {
  @ApiProperty({
    example: '0235678569',
    required: true,
  })
  @IsString()
  @Length(10, 15)
  phone?: string;

  @ApiProperty({
    example: 'johndoe@test.com',
    required: true,
  })
  @IsString()
  @IsEmail()
  @IsNotEmpty()
  email?: string;

  @ApiProperty({
    example: 'strongPass123',
    required: true,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password!: string;
}
