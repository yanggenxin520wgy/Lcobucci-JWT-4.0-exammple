<?php

namespace App\Traits;

use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Ramsey\Uuid\Uuid;

trait TokenTrait
{
    /**
     * 解析token字符串
     * @param string $jwt
     * @return Token
     */
    protected function parseToken(string $jwt): Token
    {
        $config = Configuration::forSymmetricSigner(new Sha512(), Key\InMemory::plainText($this->getKeyV2()));

        return $config->parser()->parse($jwt);
    }

    /**
     * 返回Audience
     *
     * @return string
     */
    protected function getTokenAudience(): string
    {
        return env('TOKEN_AUDIENCE', 'https://example.com');
    }

    /**
     * 返回令牌的发行时间
     *
     * @return \DateTimeImmutable
     * @throws \Throwable
     */
    protected function getTokenTimeIssuedAt(): \DateTimeImmutable
    {
        return new \DateTimeImmutable();
    }

    /**
     * 令牌可使用时间
     *
     * @return \DateTimeImmutable
     * @throws \Throwable
     */
    protected function getTokenTimeNotBefore(): \DateTimeImmutable
    {
        $now = new \DateTimeImmutable();
        return $now->modify('+' . env('TOKEN_NOT_BEFORE', 0) . 'seconds');
    }

    /**
     * @return mixed
     */
    protected function getTokenSubject()
    {
        return env('JWT_SUBJECT', 'user');
    }

    /**
     * 返回令牌过期时间
     *
     * @return \DateTimeImmutable
     * @throws \Throwable
     */
    protected function getTokenTimeExpiration(): \DateTimeImmutable
    {
        $now = new \DateTimeImmutable();
        return  $now->modify('+' . env('JWT_TIMEOUT', 86400) . ' seconds');
    }


    /**
     * @return mixed
     */
    protected function getKey()
    {
        return env('JWT_KEY', '123456');
    }

    /**
     * @return mixed
     */
    protected function getIssuer()
    {
        return env('TOKEN_ISSUER', 'https://example.com');
    }

    /**
     * @return string
     * @throws \Exception
     */
    protected function getTokenId(): string
    {
        return Uuid::uuid4()->toString();
    }
    

    /**
     * 生成token
     * @param $user
     * @return string
     * @throws \Throwable
     */
    protected function generateToken($user): string
    {
        $config = Configuration::forSymmetricSigner(new Sha512(), Key\InMemory::plainText($this->getKeyV2()));//使用对称加密算法

        $token = $config->builder()
            ->issuedBy($this->getIssuer())//配置颁发者（iss声明）
            ->withHeader('iss', $this->getIssuer())
            ->permittedFor($this->getTokenAudience())//配置访问群体（aud声明）
            ->identifiedBy($this->getTokenId())//配置jti声明
            ->relatedTo($this->getTokenSubject())//配置subject
            ->issuedAt($this->getTokenTimeIssuedAt())//配置令牌发出时间（iat）
            ->canOnlyBeUsedAfter($this->getTokenTimeNotBefore())//配置可使用令牌的时间（nbf声明）
            ->expiresAt($this->getTokenTimeExpiration())//配置令牌过期时间
            ->withClaim('uid', $user->id)//配置自定义属性
            ->getToken($config->signer(), $config->signingKey());//生成令牌

        return $token->toString();
    }


    /**
     * 验证token有效性
     * @param string $jwt token字符串
     * @return bool
     * @throws \Exception
     */
    protected function validateToken(string $jwt): bool
    {
        $config = Configuration::forSymmetricSigner(new Sha512(), Key\InMemory::plainText($this->getKeyV2()));

        $token = $config->parser()->parse($jwt);

        // 验证签发人url是否正确
        $validate_issued = new IssuedBy($this->getIssuer());
        // 验证客户端url是否匹配
        $validate_aud = new PermittedFor($this->getTokenAudience());
        // 验证subject是否正确
        $validate_subject = new RelatedTo($this->getTokenSubject());
        //验证有效期
        $validate_exp = new ValidAt(new FrozenClock(new \DateTimeImmutable()));
        
        //验证签名
        $sign = new SignedWith($config->signer(), $config->signingKey());

        $config->setValidationConstraints($sign, $validate_issued, $validate_aud, $validate_subject, $validate_exp);

        if (!$config->validator()->validate($token, ...$config->validationConstraints())) {
            return false;
        }

        return true;
    }
}
