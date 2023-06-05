# Guards

**A guard is a class annotated with the `@Injectable()` decorator, which implements the `CanActivate` interface. Guards are executed after all middleware, but before any interceptor or pipe. To create a guard, we must implement the CanActivate interface. This interface requires a canActivate method that is called every time a request is made to a route decorated with the guard. The canActivate method takes an `ExecutionContext` argument and should return a boolean value that indicates whether the route can be accessed.**

```ts
@Injectable() // auth.guard.ts
export class AuthGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    return request.headers?.authorization === 'valid_token';
  }
}
```

> **_ExecutionContext refers to the current application execution context when a request is being handled. It includes information such as: the current request, response and next function handler._**

```ts
@Get()
@UseGuards(AuthGuard)
getHello(): string {
    return "This route will only be accessible if the request includes a valid header"
}

@Controller('users')
@UseGuards(AuthGuard)
export class AppController {}

const app = await NestFactory.create(AppModule);
app.useGlobalGuards(new RolesGuard());
```

> **To apply the guard, use the `@UseGuards` decorator from NestJS and pass the guard in as an argument. We can also use guards to protect controllers, rather than just individual routes and we can use the `useGlobalGuards` method of the NestJS application instance to apply a guard at the application level.**

```ts
// role.enum.ts
export enum Role {
  Admin = 'Admin',
  Reader = 'Reader',
  Writer = 'Writer',
}
```

```ts
// roles.ts
import { SetMetadata } from '@nestjs/common';
import { Role } from './clients/entities/role.enum';

export const Roles = (...roles: Role[]) => SetMetadata('roles', roles);
```

> **_In NestJS, the `@SetMetadata` decorator is provided to attach metadata to a class or method. It stores the metadata as a key-value pair. In the above code, the key is roles, and the value is passed from the roles argument. The saved metadata can be used by the role guard later._**

```ts
// role.guard.ts
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  canActivate(context: ExecutionContext): boolean {
    // get the roles required
    const roles = this.reflector.getAllAndOverride<string[]>('roles', [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!roles) {
      return false;
    }
    const request = context.switchToHttp().getRequest();
    const userRoles = request.headers?.role?.split(',');
    return this.validateRoles(roles, userRoles);
  }

  validateRoles(roles: string[], userRoles: string[]) {
    return roles.some((role) => userRoles.includes(role));
  }
}
```

> **_In the role guard, the `getAllAndOverride` method is used to retrieve the roles. The method takes two arguments: Key: The metadata key and Targets: the set of decorated objects from which the metadata is retrieved. The above code gets the metadata for the roles key from the context of the decorated class and the decorated route handler. If different roles are associated with the class and handler, the handler metadata overrides the class metadata in the returned result. In a nutshell, the method retrieves the userRoles from the request headers and calls validateRoles to compare the user’s role with the required roles. If the user’s role is present, the method returns true to grant the user access to the resource._**

```ts
// client.controller.ts
 @Post()
  @Roles(Role.Writer)
  @UseGuards(RolesGuard)
  create(@Body() createClientDto: CreateClientDto) {
    return this.clientsService.create(createClientDto);
  }

  @Get()
  @Roles(Role.Reader)
  @UseGuards(AuthGuard, RolesGuard)
  getClients() {
    return this.clientsService.findAll();
  }
```

> **_The role guard should be used in conjunction with the Roles decorator. In this example, we assign the Writer role to the createClient endpoint, and the Reader role to the getClients endpoint. We sent a POST request and a GET request to the clients endpoint. In both requests, we set the request header with the Reader role. The GET request returns with HTTP status code 200, and the POST request is rejected with status code 401. This shows the role guard works correctly._**

**Sometimes, we may want to skip the authorization guard. For example, we may apply an AuthGuard to a controller, but one of the endpoints within the controller is intended to be public. This can be achieved by adding specific metadata to the endpoint. To begin, let’s create an AuthMetaData decorator, which can be used to set the metadata with the key 'auth' for a specific endpoint.**

```ts
import { SetMetadata } from '@nestjs/common';

export const AuthMetaData = (...metadata: string[]) =>
  SetMetadata('auth', metadata);
```

**Later, this metadata can be read by a guard. Then, we can use it to add 'skipAuthCheck' metadata to an endpoint**

```ts
@Get('hello')
@AuthMetaData('skipAuthCheck')
getPublicHello(): string { …}
```

In the AuthGuard, we add this code block to check for the skipAuthCheck metadata:

```ts
const authMetaData = this.reflector.getAllAndOverride<string[]>('auth', [
  context.getHandler(),
  context.getClass(),
]);
if (authMetaData?.includes('skipAuthCheck')) {
  return true;
}
```

> **_The addition of the above code block will allow the auth guard to skip the check if the 'skipAuthCheck' is contained in the metadata with the key of 'auth'. The SkipAuthCheck guard adds flexibility when managing access to specific endpoints._**

**NestJS allows for multiple guards to be applied to a single target at either the controller or route level. We can use the @UseGuards decorator to apply multiple guards, and the guards will be executed in the order in which they are bound. If any of the guards returns false, the request will be denied. In the example below, we use the @UseGuards decorator to combine both AuthGuard and RoleGuard to the controller.**

```ts
@Controller('clients')
@UseGuards(AuthGuard, RolesGuard)
export class ClientsController {
  // This controller will be protected by both the AuthGuard and the RoleGuard
}
```

---

```ts
// roles.decorator.ts
export enum Role {
  User = 'user',
  Admin = 'admin',
}

export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
```

```ts
// roles.guard.ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles) {
      return true;
    }
    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some((role) => user.roles?.includes(role));
  }
}
```

```ts
// auth/auth.guard.ts
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }
    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: jwtConstants.secret,
      });
      // 💡 We're assigning the payload to the request object here
      // so that we can access it in our route handlers
      request['user'] = payload;
    } catch {
      throw new UnauthorizedException();
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
```

```ts
@UseGuards(AuthGuard)
@Get('profile')
getProfile(@Request() req) {
  return req.user;
}
```

> **_Guards have a single responsibility. They determine whether a given request will be handled by the route handler or not, depending on certain conditions (like permissions, roles, ACLs, etc.) present at run-time. This is often referred to as authorization. Authorization (and its cousin, authentication, with which it usually collaborates) has typically been handled by middleware in traditional Express applications. Middleware is a fine choice for authentication, since things like token validation and attaching properties to the request object are not strongly connected with a particular route context (and its metadata). But middleware, by its nature, is dumb. It doesn't know which handler will be executed after calling the next() function. On the other hand, Guards have access to the `ExecutionContext` instance, and thus know exactly what's going to be executed next. They're designed, much like exception filters, pipes, and interceptors, to let you interpose processing logic at exactly the right point in the request/response cycle, and to do so declaratively. This helps keep your code DRY and declarative._**
