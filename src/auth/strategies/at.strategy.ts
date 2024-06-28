import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

type JwtPayload = {
  subId: string;
  email: string;
  iat: number;
  exp: number;
  refreshToken?: string;
};

export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // ingoreExpiration: false,
      secretOrKey: 'at-secret',
      // passReqToCallback: true,
    });
  }

  validate(payload: JwtPayload) {
    return payload;
  }
}
