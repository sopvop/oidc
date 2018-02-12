module OIDC.Server.Types
    ( UserStore(..)
    , CreateUserError (..)
    , InternalBackendError (..)
    , OidcServer (..)

    , OidcConfig(..)
    , OidcEnv(..)
    , initOidcEnv
    ) where

import           Katip.Monadic     (KatipContext)

import           Control.Exception (Exception)
import           Data.Time         (UTCTime)

import           OIDC.Crypto.RNG   (RNG, newRNG)
import           OIDC.Types
    (EmailAddress, Password, RememberToken, UserAuth, UserId, Username)

instance Exception InternalBackendError


data OidcEnv = OidcEnv
  { oidcConfig :: OidcConfig
  , oidcRNG    :: RNG
  }

data OidcConfig = OidcConfig
  {
  } deriving (Eq, Show)

class KatipContext m => OidcServer m where
  askOidcEnv :: m OidcEnv

initOidcEnv :: OidcConfig -> IO OidcEnv
initOidcEnv conf = OidcEnv conf <$> newRNG


-- | Some kind of internal error happend which can't be fixed
newtype InternalBackendError = InternalBackendError String
  deriving (Show)

-- | Backend error while creating user
data CreateUserError = DuplicateUsername
                     | DuplicateEmail


-- | A class implementing user storage
class UserStore m where
  -- | Lookup user in store by Id
  lookupUserById :: UserId -> m (Maybe UserAuth)
  -- | Lookup user in store by remember token used in web save by
  -- rember token
  lookupUserByRememberToken :: UserId -> m (Maybe UserAuth)
  lookupUserByUsername :: Username -> m (Maybe UserAuth)

  lockoutUser :: UserId -> UTCTime -> m ()

  -- | Store hashed remember token
  addRememberToken :: UserId -> RememberToken -> m ()

  createUser :: Username
             -> EmailAddress
             -> Password
             -> m (Either CreateUserError UserAuth)

  saveUser :: UserAuth -> m ()
