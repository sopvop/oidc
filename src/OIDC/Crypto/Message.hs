{-# LANGUAGE BangPatterns #-}
module OIDC.Crypto.Message
    ( OpaqueToken(..)
    , newOpaqueToken
    , readOpaqueToken

    , SymKey(..)
    , UrlEncrypted(..)

    , encryptExpiringPayload
    , encryptMessage
    , decryptMessage
    ) where

import           Codec.Serialise
    (Serialise, deserialiseOrFail, serialise)
import           Control.Error                    (hush)
import           Control.Monad                    (unless)
import           Control.Monad.Trans.State.Strict (modify, runState, state)
import qualified Crypto.Cipher.ChaChaPoly1305     as ChaCha
import           Crypto.Error
    (maybeCryptoError, throwCryptoErrorIO)
import           Crypto.MAC.Poly1305              (authTag)
import           Data.ByteArray                   (convert)
import           Data.ByteArray.Encoding
    (Base (Base64URLUnpadded), convertFromBase, convertToBase)
import           Data.ByteString                  (ByteString)
import qualified Data.ByteString.Lazy             as BSL
import           Data.Coerce                      (coerce)
import           Data.Time                        (UTCTime)
import           Data.Time.Clock.POSIX            (utcTimeToPOSIXSeconds)
import           Data.UUID                        (UUID)
import qualified Data.UUID                        as UUID
import           Data.Word                        (Word64)

import           OIDC.Crypto.RNG                  (RNG, randomBytes)

newtype OpaqueToken = OpaqueToken
    { unOpaqueToken :: ByteString }

newtype SymKey = SymKey
    { unSymKey :: ByteString }

newtype UrlEncrypted = UrlEncrypted
    { unUrlEncrypted :: ByteString }

urlEncrypted :: ByteString -> UrlEncrypted
urlEncrypted = UrlEncrypted . convertToBase Base64URLUnpadded

fromUrlEncrypted ::UrlEncrypted -> Maybe ByteString
fromUrlEncrypted (UrlEncrypted bs) =
   hush $ convertFromBase Base64URLUnpadded bs

newOpaqueToken :: SymKey -> RNG -> UUID -> UTCTime -> IO OpaqueToken
newOpaqueToken key rng uuid t = do
  nonce <- throwCryptoErrorIO -- TODO: should report file loc
    . ChaCha.nonce12 =<< randomBytes 12 rng
  coerce $ encryptExpiringPayload key nonce (UUID.toByteString uuid) t

readOpaqueToken :: SymKey -> OpaqueToken -> UTCTime -> Maybe UUID
readOpaqueToken key msg t = do
  uuid <- decryptExpiringPayload key (coerce msg) t
  UUID.fromByteString uuid

encryptExpiringPayload :: Serialise a
                    => SymKey
                    -> ChaCha.Nonce
                    -> a
                    -> UTCTime
                    -> IO UrlEncrypted
encryptExpiringPayload key nonce !msg !t =
    encryptMessage key nonce (msg, t0 :: Word64)
  where
    !t0 = round (utcTimeToPOSIXSeconds t)

decryptExpiringPayload :: Serialise a
                       => SymKey
                       -> UrlEncrypted
                       -> UTCTime
                       -> Maybe a
decryptExpiringPayload key msg t = do
  (decrypted, t0) <- decryptMessage key msg
  unless (seconds < t0) mempty
  pure decrypted
  where
    seconds = round (utcTimeToPOSIXSeconds t) :: Word64


encryptMessage :: Serialise p
               => SymKey
               -> ChaCha.Nonce
               -> p
               -> IO UrlEncrypted
encryptMessage key nonce !msg = do
  initial <- throwCryptoErrorIO
    $ ChaCha.initialize (unSymKey key) nonce

  let
    (bs, st) = flip runState initial $ do
       modify ChaCha.finalizeAAD
       state . ChaCha.encrypt . BSL.toStrict . serialise $ msg
    authBS = convert $ ChaCha.finalize st :: ByteString
    nonceBS = convert nonce :: ByteString
  pure . urlEncrypted
    $! BSL.toStrict
    $ serialise (nonceBS, authBS, bs)


decryptMessage :: Serialise a
               => SymKey
               -> UrlEncrypted
               -> Maybe a
decryptMessage (SymKey key) base64 = do
   msg <- fromUrlEncrypted base64
   (nonceBS, authBS, encrypted) <-
       hush $ deserialiseOrFail (BSL.fromStrict msg)
   nonce <- maybeCryptoError $ ChaCha.nonce12 (nonceBS :: ByteString)
   auth <- maybeCryptoError $ authTag (authBS :: ByteString)
   initial <- maybeCryptoError $ ChaCha.initialize key nonce
   let
      (decrypted, st) = flip runState initial $ do
         modify ChaCha.finalizeAAD
         state $ ChaCha.decrypt encrypted

      hash = ChaCha.finalize st

   unless (auth == hash) mempty

   hush $ deserialiseOrFail (BSL.fromStrict decrypted)
