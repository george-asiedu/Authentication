import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class RefreshTokenDto {
  @ApiProperty({ example: 'ghgjkjgefgyfyklVGVBYUIUI', required: true })
  @IsString()
  refresh_token!: string;
}
