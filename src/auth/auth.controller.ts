import { Body, Controller, Get, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('local/signup')
  signupLocal(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(authDto);
  }

  @Post('local/signin')
  signinLocal() {
    this.authService.signinLocal();
  }

  @Post('/logout')
  logout() {
    this.authService.logout();
  }

  @Post('/refresh')
  refreshTokens() {
    this.authService.refreshTokens();
  }
}
