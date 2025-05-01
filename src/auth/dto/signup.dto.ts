import { ApiProperty } from '@nestjs/swagger';
import {
  IsDateString,
  IsEmail,
  IsNotEmpty,
  IsString,
  Length,
  MinLength,
} from 'class-validator';

export class SignupDto {
  @ApiProperty({
    example: 'John Doe',
    required: true,
  })
  @IsString()
  @IsNotEmpty()
  name!: string;

  @ApiProperty({
    example: 'johndoe@test.com',
    required: true,
  })
  @IsString()
  @IsEmail()
  @IsNotEmpty()
  email!: string;

  @ApiProperty({
    example: '0235678569',
    required: true,
  })
  @IsString()
  @Length(10, 15)
  phone!: string;

  @ApiProperty({
    example: '25-10-2000',
    required: true,
  })
  @IsDateString()
  dob!: string;

  @ApiProperty({
    example: 'strongPass123',
    required: true,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password!: string;
}
