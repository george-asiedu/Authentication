import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length, MinLength } from 'class-validator';

export class LoginDto {
  @ApiProperty({
    example: '0235678569',
    required: true,
  })
  @IsString()
  @Length(10, 15)
  phone: string;

  @ApiProperty({
    example: 'strongPass123',
    required: true,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password!: string;
}
