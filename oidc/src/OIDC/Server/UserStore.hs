{-# LANGUAGE FlexibleInstances #-}
module OIDC.Server.UserStore
  ( HasUserStore (..)
  , lookupUserById
  , lookupUserByUsername
  , lookupUserByEmail
  , createUser
  , saveUser
  , StoreUserError(..)
  , UserStore (..)
  , RememberToken(..)
  ) where

import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.Trans.Reader (ReaderT, ask)
import           Data.Time (UTCTime)

import           OIDC.Crypto.Message (UrlEncoded)
import           OIDC.Types (EmailId, UserAuth, UserId, Username)

-- | Backend error while creating user
data StoreUserError = DuplicateUsername
                    | DuplicateEmail
  deriving(Eq,Ord,Show)

newtype RememberToken = RememberToken
  { unRememberToken :: UrlEncoded
  } deriving(Eq, Ord, Show)

-- | A class implementing user storage
data UserStore = UserStore
  { usLookupUserById
    :: UserId
    -> IO (Maybe UserAuth)
  , usLookupUserByUsername
    :: Username
    -> IO (Maybe UserAuth)
  , usLookupUserByEmail
    :: EmailId
    -> IO (Maybe UserAuth)

  , usStoreRememberToken
    :: UserId
    -> RememberToken
    -> UTCTime
    -> IO ()
  , usLookupByRememeberToken
    :: RememberToken
    -> UTCTime
    -> IO (Maybe UserAuth)
  , usDeleteRememberToken
    :: RememberToken
    -> IO ()

  , usCreateUser
    :: UserAuth
    -> IO (Either StoreUserError ())
  , usSaveUser
    :: UserAuth
    -> IO (Either StoreUserError ())
  }

class MonadIO m => HasUserStore m where
  askUserStore :: m UserStore

withUserStore
  :: HasUserStore m
  => (UserStore -> m b)
  -> m b
withUserStore act = askUserStore >>= act

instance MonadIO m => HasUserStore (ReaderT UserStore m) where
  askUserStore = ask


-- | Lookup user in store by Id
lookupUserById
  :: HasUserStore m
  => UserId
  -> m (Maybe UserAuth)
lookupUserById uid = withUserStore $ \us ->
  liftIO $ usLookupUserById us uid


lookupUserByUsername
  :: HasUserStore m
  => Username
  -> m (Maybe UserAuth)
lookupUserByUsername name = withUserStore $ \us ->
  liftIO $ usLookupUserByUsername us name

lookupUserByEmail
  :: HasUserStore m
  => EmailId
  -> m (Maybe UserAuth)
lookupUserByEmail email = withUserStore $ \us ->
  liftIO $ usLookupUserByEmail us email

createUser
  :: HasUserStore m
  => UserAuth
  -> m (Either StoreUserError ())
createUser auth = withUserStore $ \us ->
  liftIO $ usCreateUser us auth

saveUser
  :: HasUserStore m
  => UserAuth
  -> m (Either StoreUserError ())
saveUser auth = withUserStore $ \us ->
  liftIO $ usSaveUser us auth
