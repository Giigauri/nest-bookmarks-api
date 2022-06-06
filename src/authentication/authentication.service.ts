import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthenticationDto } from './dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

import * as argon from 'argon2';

@Injectable()
export class AuthenticationService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) {}

    async signup(dto: AuthenticationDto) {
        // ========== Generate the password hash ========== //

        const hash = await argon.hash(dto.password);

        // ========== Save the new user in the db ========== //

        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
            });

            return this.signToken(user.id, user.email);
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credential taken');
                }
            }

            throw error;
        }
    }

    async signin(dto: AuthenticationDto) {
        // ========== Find the user by email ========== //

        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });

        // ========== If user does not exist throw exception ========== //

        if (!user) throw new ForbiddenException('Credentials incorrect');

        // ========== Compare password ========== //

        const pwMatches = await argon.verify(user.hash, dto.password);

        // ========== If Password incorrect throw exception ========== //

        if (!pwMatches) throw new ForbiddenException('Credentials incorrect');

        // ========== Send back the user ========== //

        return this.signToken(user.id, user.email);
    }

    async signToken(
        userId: number,
        email: string
    ): Promise<{ access_token: string }> {
        const payload = {
            sub: userId,
            email,
        };

        const secret = this.config.get('JWT_SECRET');

        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: secret,
        });

        return {
            access_token: token,
        };
    }
}
