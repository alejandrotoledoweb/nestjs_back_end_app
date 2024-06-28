import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Tokens } from './types';
import { dot } from 'node:test/reporters';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signupLocal(authDto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(authDto.password);
    const newUser = await this.prismaService.user.create({
      data: {
        email: authDto.email,
        hash: hash,
      },
    });
    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async signinLocal(authDto: AuthDto): Promise<Tokens> {
    const user = await this.prismaService.user.findUnique({
      where: { email: authDto.email },
    });
    if (!user) throw new ForbiddenException('User could not be found');

    const passwordMatches = await bcrypt.compare(authDto.password, user.hash);
    if (!passwordMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: number) {
    await this.prismaService.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  async refreshTokens(userId: number, rt: string) {
    const user = await this.prismaService.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user) throw new ForbiddenException('User could not be found');

    const rtMatches = await bcrypt.compare(rt, user.hashedRt);
    if (!rtMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    return tokens;
  }

  async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        { subId: userId, email },
        {
          secret: 'at-secret',
          expiresIn: 60 * 15, //15 mins
        },
      ),
      this.jwtService.signAsync(
        { subId: userId, email },
        {
          secret: 'rt-secret',
          expiresIn: 60 * 60 * 25 * 7, // 1 week
        },
      ),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }
}
