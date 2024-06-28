import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(authDto);
  }

  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signinLocal(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signinLocal(authDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  logout(@Req() req: Request): Promise<void> {
    const user = req.user;
    console.log({ user });
    return this.authService.logout(user['subId']);
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('/refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(@Req() req: Request) {
    const user = req.user;
    console.log({ user });
    return this.authService.refreshTokens(user['subId'], user['refreshToken']);
  }
}
