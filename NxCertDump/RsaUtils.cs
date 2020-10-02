using System;
using System.Linq;
using System.Security.Cryptography;
using LibHac.Diag;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace NxCertDump
{
    internal static class RsaUtils
    {
        public static AsymmetricKeyParameter RecoverPrivateParameter(this X509Certificate obj, byte[] privateModulus)
        {
            RsaKeyParameters publicKeyParams = obj.GetPublicKey() as RsaKeyParameters;

            return RecoverRsaParameters(
                publicKeyParams.Modulus,
                publicKeyParams.Exponent,
                new BigInteger(privateModulus.Take(0x100).ToArray())
            );
        }

        public static bool IsEven(this BigInteger i)
        {
            return i.Mod(BigInteger.Two).Equals(BigInteger.Zero);
        }

        public static bool IsOne(this BigInteger i)
        {
            return i.Equals(BigInteger.One);
        }

        public static bool LessThan(this BigInteger i, BigInteger j)
        {
            return i.CompareTo(j) == -1;
        }

        public static bool GreaterThan(this BigInteger i, BigInteger j)
        {
            return i.CompareTo(j) == 1;
        }

        public static AsymmetricKeyParameter RecoverRsaParameters(BigInteger n, BigInteger e, BigInteger d)
        {
            // make sure all inputs are odd
            Assert.AssertTrue(!n.IsEven());
            Assert.AssertTrue(!e.IsEven());
            Assert.AssertTrue(!d.IsEven());

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                BigInteger k = d.Multiply(e).Subtract(BigInteger.One);

                BigInteger t = BigInteger.One;

                BigInteger r = k.Divide(BigInteger.Two);

                while (r.IsEven())
                {
                    t = t.Add(BigInteger.One);
                    r = r.Divide(BigInteger.Two);
                }

                byte[] rndBuf = n.ToByteArray();

                if (rndBuf[rndBuf.Length - 1] == 0)
                {
                    rndBuf = new byte[rndBuf.Length - 1];
                }

                BigInteger nMinusOne = n.Subtract(BigInteger.One);

                bool cracked = false;
                BigInteger y = BigInteger.Zero;

                for (int i = 0; i < 100 && !cracked; i++)
                {
                    BigInteger g;

                    do
                    {
                        rng.GetBytes(rndBuf);
                        g = new BigInteger(rndBuf);
                    } while (g.GreaterThan(n) || g.Equals(n));

                    y = g.ModPow(r, n);

                    if (y.IsOne() || y.Equals(nMinusOne))
                    {
                        i--;
                        continue;
                    }

                    for (BigInteger j = BigInteger.One; j.LessThan(t); j = j.Add(BigInteger.One))
                    {
                        BigInteger x = y.ModPow(BigInteger.Two, n);

                        if (x.IsOne())
                        {
                            cracked = true;
                            break;
                        }

                        if (x.Equals(nMinusOne))
                        {
                            break;
                        }

                        y = x;
                    }
                }

                if (!cracked)
                {
                    throw new InvalidOperationException("Prime factors not found");
                }

                BigInteger p = y.Subtract(BigInteger.One).Gcd(n);
                BigInteger q = n.Divide(p);
                BigInteger dp = d.Mod(p.Subtract(BigInteger.One));
                BigInteger dq = d.Mod(q.Subtract(BigInteger.One));
                BigInteger inverseQ = q.ModInverse(p);

                return new RsaPrivateCrtKeyParameters(
                    n,
                    e,
                    d,
                    p,
                    q,
                    dp,
                    dq,
                    inverseQ
                );
            }
        }
    }
}
