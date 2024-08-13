import { ConflictException, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { SignUpDto } from './dto/sign-up.dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto/sign-in.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { HashingService } from '../hashing/hashing.service';
import { JwtService } from '@nestjs/jwt';
import jwtConfig from '../config/jwt.config';
import { ConfigType } from '@nestjs/config';
import { ActiveUserData } from '../interfaces/active-user-data.interface';
import { User } from '@prisma/client';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { InvalidatedRefreshTokenError, RefreshTokenIdsStorage } from './refresh-token-ids.storage/refresh-token-ids.storage';
import { randomUUID } from 'crypto';

@Injectable()
export class AuthenticationService {
    constructor(
        private readonly prismaService: PrismaService,
        private readonly hashingService: HashingService,
        private readonly jwtService: JwtService,
        @Inject(jwtConfig.KEY)
        private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
        private readonly refreshTokenIdsStorage: RefreshTokenIdsStorage,
    ) { }

    async signUp(signUpDto: SignUpDto) {
        try {
            const existingUser = await this.prismaService.user.findUnique({
                where: { email: signUpDto.email },
            });

            if (existingUser) {
                throw new ConflictException('User already exists');
            }

            const hashedPassword = await this.hashingService.hash(signUpDto.password);
            await this.prismaService.user.create({
                data: {
                    email: signUpDto.email,
                    password: hashedPassword,
                },
            });
        } catch (err) {
            throw err;
        }
    }

    async signIn(signInDto: SignInDto) {
        const user = await this.prismaService.user.findUnique({
            where: { email: signInDto.email },
        });

        if (!user) {
            throw new UnauthorizedException('User does not exist');
        }

        const isEqual = await this.hashingService.compare(signInDto.password, user.password);
        if (!isEqual) {
            throw new UnauthorizedException('Password does not match');
        }

        return await this.generateTokens(user);
    }

    async generateTokens(user: { id: number; email: string; password: string; }) {
        const refreshTokenId = randomUUID();
        const [accessToken, refreshToken] = await Promise.all([this.signToken<Partial<ActiveUserData>>(user.id, this.jwtConfiguration.accessTokenTtl, { email: user.email }),
        this.signToken(user.id, this.jwtConfiguration.refreshTokenTtl, {
            refreshTokenId,
        }),
        ]);

        return {
            accessToken,
            refreshToken,
        };
    }

    async refreshTokens(refreshTokenDto: RefreshTokenDto) {
        try {
            const { sub, refreshTokenId } = await this.jwtService.verifyAsync<Pick<ActiveUserData, 'sub'> & { refreshTokenId: string }>(refreshTokenDto.refreshToken, {
                secret: this.jwtConfiguration.secret,
                audience: this.jwtConfiguration.audience,
                issuer: this.jwtConfiguration.issuer,
            });
            const user = await this.prismaService.user.findUniqueOrThrow({
                where: {
                    id: sub,
                }
            });
            const isValid = await this.refreshTokenIdsStorage.validate(
                user.id,
                refreshTokenId,
            );
            if (isValid) {
                await this.refreshTokenIdsStorage.invalidate(user.id);
            } else {
                throw new Error('Refresh Token is Invalid.');
            }
            return this.generateTokens(user);
        } catch (err) {
            if (err instanceof InvalidatedRefreshTokenError) {
                throw new UnauthorizedException('Access Denied');
            }
            throw new UnauthorizedException();
        }
    }

    private async signToken<T>(userId: number, expiresIn: number, payload?: T) {
        return await this.jwtService.signAsync({
            sub: userId,
            ...payload,
        },
            {
                audience: this.jwtConfiguration.audience,
                issuer: this.jwtConfiguration.issuer,
                secret: this.jwtConfiguration.secret,
                expiresIn,
            }
        );
    }
}
