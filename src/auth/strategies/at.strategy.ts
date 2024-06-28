import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // ingoreExpiration: false,
      secretOrPrivateKey: 'at-secret',
      // passReqToCallback: true,
    });
  }

  validate(payload: any) {
    return payload;
  }
}
