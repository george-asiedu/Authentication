import { PostgresConnectionOptions } from 'typeorm/driver/postgres/PostgresConnectionOptions';
import { ConfigService } from '@nestjs/config';

export const pgConfig = (
  configService: ConfigService,
): PostgresConnectionOptions => ({
  type: 'postgres',
  url: configService.get<string>('DB_CONNECTION'),
  entities: [__dirname + '/../**/*.entity{.ts,.js}'],
  synchronize:
    configService.get<string>('NODE_ENV') !== 'production'
      ? configService.get<boolean>('DB_SYNC', true)
      : false,
  extra: {
    charset: 'utf8mb4_unicode_ci',
  },
  ssl: {
    rejectUnauthorized: false,
  },
});
