# [Interceptors](https://docs.nestjs.com/interceptors)

**NestJS interceptors are class-annotated with injectable decorators and implement the `NestInterceptor` interface. This interface has two methods: `intercept` and `handleRequest`. The intercept method is called before sending the request to a controller, while the handleRequest method is called after the request has been processed by the controller and a response is returned. Interceptors are the most powerful form of the request-response pipeline. They have direct access to the request before hitting the route handler. We can mutate the response after it has passed through the route handler.**

**The `intercept` method is a method that implements a custom interceptor. It takes in two arguments, namely: `ExecutionContext` and `CallHandler`. The ExecutionContext is an object that provides methods to access the route handler and class that can be called or invoked. The CallHandler is an interface that provides access to an Observable, which represents the response stream from the route handler.**

![Interceptors](https://docs.nestjs.com/assets/Interceptors_1.png)

```ts
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    console.log('Before...');

    const now = Date.now();
    return next
      .handle()
      .pipe(tap(() => console.log(`After... ${Date.now() - now}ms`)));
  }
}
```

> **_Since `handle()` returns an RxJS Observable, we have a wide choice of operators we can use to manipulate the stream. In the example above, we used the tap() operator, which invokes our anonymous logging function upon graceful or exceptional termination of the observable stream, but doesn't otherwise interfere with the response cycle. Interceptors, like controllers, providers, guards, and so on, can inject dependencies through their constructor._**

```ts
@Get()
 @UseInterceptors(CustomInterceptors)
 getUsers(): User[] {
   return this.appService.getUsers();
 }

@Controller()
@UseInterceptors(CustomInterceptors)
export class AppController {}

app.useGlobalInterceptors(new CustomInterceptors());
await app.listen(3000);

 providers: [
   {
     provide: APP_INTERCEPTOR,
     useClass: CustomInterceptors,
   },
 ],
```

> **_The CustomInterceptor will be applied across the entire application for all the controllers and router handlers. However, if we register our CustomInterceptor globally, we will not be able to inject any dependencies which are defined within a modular scope. To solve this, we can register our interceptor within a scoped module._**

---

```ts
import { CallHandler, ExecutionContext, NestInterceptor } from '@nestjs/common';
import { map, Observable } from 'rxjs';
import { User } from 'src/app.service';

export class CustomInterceptors implements NestInterceptor {
  intercept(context: ExecutionContext, handler: CallHandler): Observable<any> {
    console.log('Before...');

    return handler.handle().pipe(
      map((data) =>
        data.map((item: User) => {
          console.log('After....');
          const res = {
            ...item,
            firstName: item.first_name,
            lastName: item.last_name,
          };
          delete res.first_name, delete res.last_name;
          return res;
        }),
      ),
    );
  }
}
```

```ts
export class LoggerInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    console.log('Before...');

    const req = context.switchToHttp().getRequest();
    const method = req.method;
    const url = req.url;
    console.log(`Method: ${method}, URL: ${url}`);

    const now = Date.now();
    return next.handle().pipe(
      map((data) => {
        Logger.log(
          `${method} ${url} ${Date.now() - now}ms`,
          context.getClass().name,
        ),
          console.log('After...');
        return data;
      }),
    );
  }
}
```

```ts
export class AuthInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, handler: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest();
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    console.log('token', token);
    console.log('auth', authHeader);
    if (!token) {
      throw new UnauthorizedException('No token provided');
    }
    return handler.handle();
  }
}
```

```ts
export class TimeoutInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      timeout(5000),
      catchError((err) => {
        if (err instanceof TimeoutError) {
          return throwError(() => new RequestTimeoutException());
        }
        return throwError(() => err);
      }),
    );
  }
}
```

[Logrocket](https://blog.logrocket.com/nestjs-interceptors-guide-use-cases/)
