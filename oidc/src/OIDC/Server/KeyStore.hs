{-# LANGUAGE FlexibleInstances #-}
module OIDC.Server.KeyStore
  ( KeyStore(..)
  , HasKeyStore(..)
  , askAccessTokenSigningKey
  , askVerificationKeys
  ) where

import           Crypto.JWT (JWK)
import           OIDC.Crypto.Jwk (PublicKeySet (..))

import           Control.Monad.IO.Class (MonadIO, liftIO)

data KeyStore = KeyStore
  { ksAskAccessTokenSigningKey :: IO JWK
  , ksAskVerificationKeys      :: IO PublicKeySet
  }

class MonadIO m => HasKeyStore m where
  askKeyStore :: m KeyStore


withKeyStore
  :: HasKeyStore m
  => (KeyStore -> m b)
  -> m b
withKeyStore act = askKeyStore >>= act

askAccessTokenSigningKey
  :: HasKeyStore m
  => m JWK
askAccessTokenSigningKey =
  withKeyStore  (liftIO . ksAskAccessTokenSigningKey)

askVerificationKeys
  :: HasKeyStore m
  => m PublicKeySet
askVerificationKeys = withKeyStore (liftIO . ksAskVerificationKeys)
