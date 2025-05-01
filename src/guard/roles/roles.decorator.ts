import { SetMetadata } from '@nestjs/common';
import { constants } from '../../utils/constants';
import { UserRole } from 'src/model/role.enum';

const ROLES_KEY = constants.ROLES_KEY;
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
