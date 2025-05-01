import { ApiProperty } from '@nestjs/swagger';
import { UserRole } from 'src/model/role.enum';

export class SignupResponseDto {
  @ApiProperty({ example: 'd290f1ee-6c54-4b01-90e6-d701748f0851' })
  id!: string;

  @ApiProperty({ example: '123456', nullable: true })
  code!: string | null;

  @ApiProperty({ example: 'johndoe@test.com' })
  email!: string;

  @ApiProperty({ example: '0235678569' })
  phone!: string;

  @ApiProperty({ example: 'John Doe' })
  name!: string;

  @ApiProperty({ enum: UserRole, example: UserRole.User })
  role!: UserRole;
}
