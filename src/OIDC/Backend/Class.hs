module OIDC.Backend.Class
    ( UserStore(..)
    , CreateUserError (..)
    , InternalBackendError (..)
    ) where


import           Control.Exception (Exception)
import           Data.Time         (UTCTime)

import           OIDC.Types
    (EmailAddress, Password, RememberToken, UserAuth, UserId, Username)

instance Exception InternalBackendError

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
