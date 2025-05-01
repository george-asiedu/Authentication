import { Request } from 'express';
import { User } from '../entities/user.entity';

export interface SignInResponse {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    name: string;
    phone: string;
    role: string;
    dob: string;
  };
}

export interface ResponseInterceptor<T> {
  message: string;
  data: T;
}

export interface JwtPayload {
  userId: string;
}

export interface RequestInterface extends Request {
  user: User;
}
