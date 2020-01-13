using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace MusicToken
{
    public static class TokenGenerator
    {
        private static string CreateSignedJwt(ECDsa eCDsa,
                                              string teamId,
                                              string keyId,
                                              DateTime expiration)
        {
            var now = DateTime.UtcNow;
            var tokenHandler = new JwtSecurityTokenHandler();

            var jwtToken = tokenHandler.CreateJwtSecurityToken(
                issuer: teamId,
                subject: null,
                notBefore: now,
                expires: expiration,
                issuedAt: now,
                signingCredentials: new SigningCredentials(
                    new ECDsaSecurityKey(eCDsa) { KeyId = keyId }, SecurityAlgorithms.EcdsaSha256));

            return tokenHandler.WriteToken(jwtToken);
        }

        public static string GenerateToken(string privateKey,
                                           string teamId,
                                           string keyId,
                                           TimeSpan lifeSpan)
        {
            var ECDsa = LoadPrivateKey(privateKey);
            var expiration = DateTime.UtcNow.Add(lifeSpan);
            var jwt = CreateSignedJwt(ECDsa, teamId, keyId, expiration);
            return jwt;
        }

        private static ECDsa LoadPrivateKey(string privateKey)
        {
            var ecDsaCng = new ECDsaCng(CngKey.Import(Convert.FromBase64String(privateKey), CngKeyBlobFormat.Pkcs8PrivateBlob))
            {
                HashAlgorithm = CngAlgorithm.ECDsaP256
            };
            return ecDsaCng;
        }
    }
}
