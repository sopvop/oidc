{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
module OIDC.Crypto.Password
    ( Password(..)
    , CleartextPassword(..)
    , verifyPassword
    ) where

import           Control.Error           (hush)
import           Control.Monad           (unless)

import           Data.Maybe              (fromMaybe)
import           Data.Semigroup          ((<>))
import           Data.Text               (Text)
import qualified Data.Text.Encoding      as Text
import           Data.Text.ICU.Normalize (NormalizationMode (NFKC), normalize)

import           Crypto.Error            (CryptoFailable)
import qualified Crypto.KDF.Argon2       as A2
import qualified Crypto.KDF.BCrypt       as BC
import qualified Crypto.KDF.PBKDF2       as PB
import           Data.ByteArray.Encoding
    (Base (Base64OpenBSD), convertFromBase, convertToBase)
import           Data.ByteString         (ByteString)
import           Data.ByteString.Builder as BL
import qualified Data.ByteString.Char8   as BSC
import qualified Data.ByteString.Lazy    as BL
import           Web.HttpApiData         (FromHttpApiData)

import           OIDC.Crypto.RNG         (RNG, randomBytes)

argon2 = A2.hash (A2.Options 2 512 2 A2.Argon2i A2.Version13) ("x"::ByteString) ("somesalt"::ByteString) 32 :: CryptoFailable ByteString

bcrypt = BC.bcrypt 12 ("somesaltsomesalt" :: ByteString) ("x"::ByteString) :: ByteString
pb = PB.fastPBKDF2_SHA256 (PB.Parameters (2 ^ 17) 32) ("x"::ByteString) ("somesalt"::ByteString) :: ByteString

newtype Password = Password ByteString
    deriving(Eq, Ord)
instance Show Password where
  show _ = "Password"

newtype CleartextPassword = CleartextPassword Text
    deriving (Eq, Ord, FromHttpApiData)
instance Show CleartextPassword where
  show _ = "CleartextPassword"

verifyPassword clr passwd@(Password bs) = fromMaybe False $ case split of
   (algo : params) -> case algo of
     "pbkdf2_sha256" ->
        parsePbkdf2Sha256 params >>= verifyPbkdf2Sha256 clr
     "2a" -> pure $ verifyBcrypt clr passwd
     _               -> Nothing
   _               -> Nothing
  where
    split = BSC.split '$' $ BSC.drop 1 bs

parsePbkdf2Sha256 :: [ByteString] -> Maybe (PB.Parameters, ByteString, ByteString)
parsePbkdf2Sha256 [roundsBS, saltB64, hashB64] = do
  (rounds, res) <- BSC.readInt roundsBS
  unless (BSC.null res) Nothing

  salt <- fromBase64 saltB64
  unless (BSC.length salt == 16) Nothing

  hash <- fromBase64 hashB64
  unless (BSC.length hash == 32) Nothing

  let params = PB.Parameters rounds (BSC.length hash)
  Just (params, salt, hash)

parsePbkdf2Sha256 _ = Nothing

verifyPbkdf2Sha256 clr (params, salt, hash) =
   Just $ PB.fastPBKDF2_SHA256 params salt (cleartextToBS clr) == hash


verifyBcrypt clr (Password ps) = BC.validatePassword (cleartextToBS clr) ps

cleartextToBS (CleartextPassword ps) = Text.encodeUtf8 (normalize NFKC ps)

generatePbkdf2Sha256 :: RNG -> CleartextPassword -> IO Password
generatePbkdf2Sha256 rng clr = do
  salt <- randomBytes 16 rng
  let hashB64 = toBase64 . PB.fastPBKDF2_SHA256 params salt
               $ cleartextToBS clr
      saltB64 = toBase64 salt
      itersBS = BL.intDec (PB.iterCounts params)

  pure . Password . BL.toStrict . BL.toLazyByteString $
     "$pbkdf2_sha256$" <> itersBS <> BL.char8 '$'
                       <> BL.byteString saltB64 <> BL.char8 '$'
                       <> BL.byteString hashB64
  where
    params = PB.Parameters 100000 32


fromBase64 :: ByteString -> Maybe ByteString
fromBase64 = hush . convertFromBase Base64OpenBSD

toBase64 :: ByteString -> ByteString
toBase64 = convertToBase Base64OpenBSD


