import { Controller, Get, Post } from '@nestjs/common';

@Controller('auth')
export class AuthController {
  @Get('/index')
  login() {
    return 'login page';
  }

  @Get('')
  logout() {
    return 'logout page';
  }
}
