{-# LANGUAGE BangPatterns #-}
module OIDC.Server.UserStore.Memory
  ( initUserStore
  ) where

import           Control.Monad (when)
import           Data.ByteString.Short (ShortByteString)
import           Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HashMap
import           Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef)
import           Data.Maybe (fromMaybe)
import           Data.Time (UTCTime)

import           OIDC.Server.UserStore
    (RememberToken (..), StoreUserError (..), UserStore (..))
import           OIDC.Types (EmailId (..), UserAuth (..), UserId (..), Username)

data Store = Store
  { userMap     :: HashMap UserId UserAuth
  , usernameMap :: HashMap Username UserId
  , emailMap    :: HashMap EmailId UserId
  , rememberMap :: HashMap ShortByteString (UserId, UTCTime)
  }

newtype MemoryUserStore = MemoryUserStore
  { unMemoryUserStore :: IORef Store
  }

msLookupById
  :: MemoryUserStore
  -> UserId
  -> IO (Maybe UserAuth)
msLookupById ms uid = HashMap.lookup uid . userMap
                      <$> readIORef (unMemoryUserStore ms)

msLookupByUsername
  :: MemoryUserStore
  -> Username
  -> IO (Maybe UserAuth)
msLookupByUsername ms uname =
  go <$> readIORef (unMemoryUserStore ms)
  where
    go s = HashMap.lookup uname (usernameMap s)
           >>= flip HashMap.lookup (userMap s)

msLookupByEmail
  :: MemoryUserStore
  -> EmailId
  -> IO (Maybe UserAuth)
msLookupByEmail ms email =
  go <$> readIORef (unMemoryUserStore ms)
  where
    go s = HashMap.lookup email (emailMap s)
           >>= flip HashMap.lookup (userMap s)

addUserToStore
  :: UserAuth
  -> Store
  -> Store
addUserToStore !usr !store =
    store { userMap = um
          , usernameMap = unm
          , emailMap = em
          }
  where
    uid = userId usr
    um = HashMap.insert uid usr $ userMap store
    unm = HashMap.insert (userUsername usr) uid
          $ usernameMap store
    em = HashMap.insert (userEmailId usr) uid
         $ emailMap store

dropUserFromStore
  :: UserId
  -> Store
  -> Store
dropUserFromStore uid store = fromMaybe store $ do
  usr <- HashMap.lookup uid (userMap store)
  pure $ store { userMap = HashMap.delete uid (userMap store)
               , usernameMap = HashMap.delete (userUsername usr)
                               $ usernameMap store
               , emailMap = HashMap.delete (userEmailId usr)
                            $ emailMap store
               }

checkUser
  :: UserAuth
  -> Store
  -> Either StoreUserError ()
checkUser user s = do
    when usernameTaken $ Left DuplicateUsername
    when emailTaken $ Left DuplicateEmail
  where
    usernameTaken = HashMap.member (userUsername user) (usernameMap s)
    emailTaken = HashMap.member (userEmailId user) (emailMap s)


msSaveUser
  :: MemoryUserStore
  -> UserAuth
  -> IO (Either StoreUserError ())
msSaveUser ms user =
  atomicModifyIORef' (unMemoryUserStore ms) $ \s0 ->
     let s = dropUserFromStore (userId user) s0
     in case checkUser user s of
       Left e -> (s, Left e)
       Right () -> (addUserToStore user s, Right ())


msStoreRememberToken
  :: MemoryUserStore
  -> UserId
  -> RememberToken
  -> UTCTime
  -> IO ()
msStoreRememberToken ms uid token t =
  atomicModifyIORef' (unMemoryUserStore ms) $ \s0 ->
    let rm = rememberMap s0
        userExists = HashMap.member uid $ userMap s0
    in if userExists
       then (s0 { rememberMap = HashMap.insert bs (uid,t) rm }, ())
       else (s0, ())
  where
    RememberToken bs = token

msLookupByRememberToken
  :: MemoryUserStore
  -> RememberToken
  -> UTCTime
  -> IO (Maybe UserAuth)
msLookupByRememberToken ms token t =
  atomicModifyIORef' (unMemoryUserStore ms) $ \s0 ->
     let
       um = userMap s0
       rm = rememberMap s0
     in case HashMap.lookup bs rm of
       Nothing -> (s0, Nothing)
       Just (uid, t0)
         | t0 < t -> (s0 { rememberMap = HashMap.delete bs rm} , Nothing)
         | otherwise -> case HashMap.lookup uid um of
             Nothing -> (s0 { rememberMap = HashMap.delete bs rm} , Nothing)
             Just u -> (s0, Just u)
  where
    RememberToken bs = token

msDeleteRememberToken
  :: MemoryUserStore
  -> RememberToken
  -> IO ()
msDeleteRememberToken ms token =
  atomicModifyIORef' (unMemoryUserStore ms) $ \s0 ->
     let
       rm = rememberMap s0
     in (s0 { rememberMap = HashMap.delete bs rm }, ())
  where
    RememberToken bs = token

initUserStore
  :: [UserAuth]
  -> IO UserStore
initUserStore usrs = mkUserStore <$> newIORef store
  where
    s0 = Store mempty mempty mempty mempty
    store = foldr addUserToStore s0 usrs
    mkUserStore !s =
      let ms = MemoryUserStore s
      in UserStore
         { usLookupUserById = msLookupById ms
         , usLookupUserByUsername = msLookupByUsername ms
         , usLookupUserByEmail = msLookupByEmail ms
         , usStoreRememberToken = msStoreRememberToken ms
         , usLookupByRememeberToken = msLookupByRememberToken ms
         , usDeleteRememberToken = msDeleteRememberToken ms
         , usCreateUser = msSaveUser ms
         , usSaveUser = msSaveUser ms
         }
