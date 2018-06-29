{-# LANGUAGE DeriveGeneric #-}
module OIDC.Web.Session
  ( Session(..)
  , FlashMessage(..)
  ) where

import           Codec.Serialise (Serialise)
import           Crypto.Random
import           Data.ByteString (ByteString)
import           Data.ByteString.Short (ShortByteString)
import           Data.IORef (IORef, atomicModifyIORef')
import           Data.Text (Text)
import qualified Data.Text.Encoding as Text
import           Data.Time (getCurrentTime)
import           Data.Vault.Strict (Key, newKey)
import           GHC.Generics (Generic)
import qualified Network.Wai.Session as Wai

import           OIDC.Crypto.Message
    (SymKey (..), UrlEncoded, decryptExpiringPayload, encryptExpiringPayload)
import           OIDC.Crypto.RNG (RNG, randomBytes)

data FlashMessage
  = RegistrationMailSent Text
  | PasswordChanged
  deriving(Show, Generic)

instance Serialise FlashMessage

data Session = Session
  { sessionMessages :: [FlashMessage]
  , sessionCSRF     :: Text
  } deriving(Show, Generic)


instance Serialise Session


data SessionEnv = SessionEnv
  { sessionKey       :: Key Session
  , sessionRNG       :: RNG
  , sessionCryptoKey :: SymKey
  }


newSession :: RNG -> IO Session
newSession rng = do
  t <- getCurrentTime
  Session [] . Text.decodeLatin1
      <$> randomBytes 16 rng

