import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class VerifyAccountDto {
  @ApiProperty({ example: '787643', required: true })
  @IsString()
  code!: string;
}
