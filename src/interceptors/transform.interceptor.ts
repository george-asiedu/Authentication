import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ResponseInterceptor } from '../model/auth.model';

@Injectable()
export class TransformInterceptor<T>
  implements NestInterceptor<T, ResponseInterceptor<T>>
{
  intercept(
    _context: ExecutionContext,
    next: CallHandler,
  ): Observable<ResponseInterceptor<T>> {
    return next.handle().pipe(map((data) => ({ message: 'Success', data })));
  }
}
