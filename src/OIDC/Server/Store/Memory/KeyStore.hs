module OIDC.Server.Store.Memory.KeyStore
  ( initMemoryKeyStore
  ) where

import           Control.Concurrent.MVar
    (modifyMVar, newMVar, readMVar, MVar)

import           Crypto.JWT              (JWK, JWKSet (..))
import           Data.Time               (UTCTime, addUTCTime, getCurrentTime, NominalDiffTime)
import           OIDC.Server.Types       (KeyStore (..))

import           OIDC.Crypto.Jwk
    (PublicKeySet (..), generateEd25519, toPublicKeySet)
import           OIDC.Crypto.RNG         (newRNG)

data Store = Store
  { currentKey   :: JWK
  , nextUpdateAt :: UTCTime
  , verifyKeys   :: PublicKeySet
  , oldKeys      :: [(UTCTime, JWK)]
  }

activeKey :: NominalDiffTime -> MVar Store -> IO JWK
activeKey expire ref = do
  t <- getCurrentTime
  modifyMVar ref $ \s ->
    if nextUpdateAt s > t
    then pure (s, currentKey s)
    else do
      k <- generateNewKey
      let
        keyExpires = addUTCTime (expire / 2) t
        nextUpdate = addUTCTime expire t
        keys = (keyExpires, currentKey s)
               : filter (\(e, _) -> e > t)
                 (oldKeys s)
        !s' = s { currentKey = k
                , nextUpdateAt = nextUpdate
                , verifyKeys = toPublicKeySet (JWKSet $ map snd keys)
                , oldKeys = keys
                }
      pure (s', k)

publicKeys :: MVar Store -> IO PublicKeySet
publicKeys ref = verifyKeys <$> readMVar ref

generateNewKey :: IO JWK
generateNewKey = do
  rng <- newRNG
  generateEd25519 rng

initMemoryKeyStore :: NominalDiffTime -> Maybe JWK -> IO KeyStore
initMemoryKeyStore expire initKey = do
  t <- getCurrentTime
  key <- maybe generateNewKey pure initKey
  let s = Store key (addUTCTime (expire /2) t)
          (toPublicKeySet (JWKSet [key]))
          [(addUTCTime expire t , key)]

  v <- newMVar s
  pure $ KeyStore (activeKey expire v) (publicKeys v)
