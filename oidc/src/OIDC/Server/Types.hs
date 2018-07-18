{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
module OIDC.Server.Types
    ( InternalBackendError (..)

    , ServerM(..)
    , runServerM

    , OidcConfig(..)
    , OidcEnv(..)
    , initOidcEnv
    ) where

import           Control.Exception (Exception)
import           Control.Monad.Catch (MonadCatch, MonadThrow)
import           Control.Monad.IO.Class (MonadIO)
import           Control.Monad.Reader (MonadReader, ReaderT (..), asks, local)
import           Data.Time (NominalDiffTime)
import           Katip (Katip (..), LogEnv, Namespace)
import           Katip.Monadic (KatipContext (..), LogContexts)

import           OIDC.Crypto.RNG (RNG, newRNG)

import           OIDC.Server.ClientStore (ClientStore, HasClientStore (..))
import           OIDC.Server.KeyStore (HasKeyStore (..), KeyStore)
import           OIDC.Server.UserStore (HasUserStore (..), UserStore)

instance Exception InternalBackendError


data OidcEnv = OidcEnv
  { oidcConfig         :: !OidcConfig
  , oidcUserStore      :: !UserStore
  , oidcClientStore    :: !ClientStore
  , oidcKeysStore      :: !KeyStore
  , oidcKatipLogEnv    :: !LogEnv
  , oidcKatipContext   :: !LogContexts
  , oidcKatipNamespace :: !Namespace
  , oidcRNG            :: !RNG
  }

newtype OidcConfig = OidcConfig
  { confKeysExpiration :: NominalDiffTime
  } deriving (Eq, Show)


initOidcEnv :: UserStore
            -> ClientStore
            -> KeyStore
            -> OidcConfig
            -> LogEnv -> IO OidcEnv
initOidcEnv store cl keys conf logEnv =
   OidcEnv conf store cl keys logEnv mempty ns <$> newRNG
  where
    ns = "oidc"

newtype ServerM a = ServerM
  { unServerM :: ReaderT OidcEnv IO a
  } deriving ( Functor, Monad, Applicative, MonadReader OidcEnv
             , MonadIO, MonadThrow, MonadCatch )

runServerM :: ServerM a -> OidcEnv -> IO a
runServerM act = runReaderT (unServerM act)


instance Katip ServerM where
  getLogEnv = asks oidcKatipLogEnv
  {-# INLINE getLogEnv #-}
  localLogEnv f =
      local $ \e@OidcEnv {oidcKatipLogEnv = env} ->
          e { oidcKatipLogEnv = f env }
  {-# INLINE localLogEnv #-}

instance KatipContext ServerM where
  getKatipContext = asks oidcKatipContext
  {-# INLINE getKatipContext #-}
  localKatipContext f =
      local $ \e@OidcEnv {oidcKatipContext = ctx} ->
          e { oidcKatipContext = f ctx }
  {-# INLINE localKatipContext #-}
  getKatipNamespace = asks oidcKatipNamespace
  {-# INLINE getKatipNamespace #-}
  localKatipNamespace f =
      local $ \e@OidcEnv {oidcKatipNamespace = ctx} ->
          e { oidcKatipNamespace = f ctx }
  {-# INLINE localKatipNamespace #-}


instance HasUserStore ServerM where
  askUserStore = asks oidcUserStore

instance HasKeyStore ServerM where
  askKeyStore = asks oidcKeysStore

instance HasClientStore ServerM where
  askClientStore = asks oidcClientStore

-- | Some kind of internal error happend which can't be fixed
newtype InternalBackendError = InternalBackendError String
  deriving (Show)
