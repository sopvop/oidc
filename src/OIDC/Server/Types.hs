{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
module OIDC.Server.Types
    ( UserStore(..)
    , StoreUserError (..)
    , InternalBackendError (..)

    , ClientStore(..)

    , ServerM(..)
    , runServerM
    , lookupUserByUsername
    , lookupClientById
    , askAccessTokenSigningKey
    , askPublicKeys

    , OidcConfig(..)
    , OidcEnv(..)
    , initOidcEnv
    , KeyStore(..)
    ) where

import           Control.Exception      (Exception)
import           Control.Monad.Catch    (MonadCatch, MonadThrow)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.Reader   (MonadReader, ReaderT (..), asks, local)
import           Crypto.JWT             (JWK)
import           Data.Time              (NominalDiffTime, addUTCTime)
import           Katip                  (Katip (..), LogEnv, Namespace)
import           Katip.Monadic          (KatipContext (..), LogContexts)

import           OIDC.Crypto.Jwk        (PublicKeySet (..))
import           OIDC.Crypto.RNG        (RNG, newRNG)
import           OIDC.Types
    (ClientAuth, ClientId, EmailId, UserAuth, UserId, Username)

instance Exception InternalBackendError


data OidcEnv = OidcEnv
  { oidcConfig         :: !OidcConfig
  , oidcStore          :: !UserStore
  , oidcClients        :: !ClientStore
  , oidcKeys           :: !KeyStore
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

-- | Some kind of internal error happend which can't be fixed
newtype InternalBackendError = InternalBackendError String
  deriving (Show)

-- | Backend error while creating user
data StoreUserError = DuplicateUsername
                    | DuplicateEmail
  deriving(Eq,Ord,Show)

-- | A class implementing user storage
data UserStore = UserStore
  { storeLookupUserById       :: UserId -> IO (Maybe UserAuth)
  -- ^ Lookup user in store by Id
--  , storeLookupUserByRememberToken :: UserId -> IO (Maybe UserAuth)
--  -- ^ Lookup user in store by remember token used in web save by
--  -- rember token
  , storeLookupUserByUsername :: Username -> IO (Maybe UserAuth)
  , storeLookupUserByEmail    :: EmailId -> IO (Maybe UserAuth)

--  , storeLockoutUser :: UserId -> UTCTime -> IO ()

--  , storeAddRememberToken :: UserId -> RememberToken -> IO ()
--  -- ^ Store hashed remember token

  , storeCreateUser           :: UserAuth -> IO (Either StoreUserError ())
  , storeSaveUser             :: UserAuth -> IO (Either StoreUserError ())
  }

lookupUserByUsername :: Username -> ServerM (Maybe UserAuth)
lookupUserByUsername nm = do
  us <- asks oidcStore
  liftIO $ storeLookupUserByUsername us nm


newtype ClientStore = ClientStore
  { storeLookupClientById :: ClientId -> IO (Maybe ClientAuth)
  }

lookupClientById :: ClientId -> ServerM (Maybe ClientAuth)
lookupClientById cid = do
  cs <- asks oidcClients
  liftIO $ storeLookupClientById cs cid

data KeyStore = KeyStore
  { storeAccessTokenSigningKey :: IO JWK
  , storePublicKeys            :: IO PublicKeySet
  }

askAccessTokenSigningKey :: ServerM JWK
askAccessTokenSigningKey = do
  us <- asks oidcKeys
  liftIO $ storeAccessTokenSigningKey us


askPublicKeys :: ServerM PublicKeySet
askPublicKeys = do
  us <- asks oidcKeys
  liftIO $ storePublicKeys us

