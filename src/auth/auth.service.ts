import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from './utils';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async register(authDto: AuthDto) {
    try {
      const hashPassword = await argon.hash(authDto.password);
      const user = await this.prisma.user.create({
        data: {
          email: authDto.email,
          hash: hashPassword,
        },
      });
      return this.signToken(user.id, user.email);
    } catch (e) {
      if (e instanceof PrismaClientKnownRequestError) {
        if (e.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw e;
    }
  }

  async login(authDto: AuthDto) {
    const throwForbidden = (msg: string) => {
      throw new ForbiddenException(msg);
    };
    const user = await this.prisma.user.findUnique({
      where: {
        email: authDto.email,
      },
    });
    if (!user) {
      throwForbidden('Credentials incorrect');
    }
    const pwMatch = await argon.verify(user.hash, authDto.password);
    if (!pwMatch) {
      throwForbidden('Wrong password');
    }
    return this.signToken(user.id, user.email);
  }

  private async signToken(userId: number, email: string) {
    const payload: JwtPayload = {
      sub: userId,
      email,
    };
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: this.config.get('JWT_SECRET'),
    });
    return {
      accessToken: token,
    };
  }
}
