{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE QuasiQuotes                #-}
module OIDC.Backend.Postgres
    ( runPostgresBackend
    , PostgresBackend
    ) where

import           Control.Error                    (headMay)
import           Control.Monad.Catch              (throwM)
import           Control.Monad.IO.Class           (MonadIO, liftIO)
import           Control.Monad.Trans.Reader       (ReaderT, ask, runReaderT)
import           Data.Pool                        (Pool, withResource)
import qualified Data.Text.Encoding               as Text
import           Data.Time                        (UTCTime)

import           OIDC.Types
    (EmailAddress, Password (..), UserAuth (..), UserId, Username)

import qualified Database.PostgreSQL.Simple       as PG
import           Database.PostgreSQL.Simple.SqlQQ (sql)

import           OIDC.Backend.Class
    (CreateUserError (..), InternalBackendError (..), UserStore (..))

-- | Create new user in database
pgCreateUser :: PG.Connection
             -> Username
             -> EmailAddress
             -> Password
             -> IO (Either CreateUserError UserAuth)
pgCreateUser con username email passwd@(Password passwdBS) = do
  u <- fmap toUserAuth . headMay <$> PG.query con
    [sql| SELECT user_id
          FROM create_user(username := ?, email := ?, passwd := ?)
     |] (username, email, Text.decodeLatin1 passwdBS)
  maybe (throwM err) (pure . Right) u
  where
    toUserAuth (PG.Only uid) = UserAuth uid username email passwd Nothing
    err = InternalBackendError "create_user returned Nothing"


-- | Lookup user in database by Id
pgLookupUserById :: PG.Connection -> UserId -> IO (Maybe UserAuth)
pgLookupUserById con uid =
  fmap toUserAuth . headMay <$> PG.query con
    [sql| SELECT username, email, passwd, locked_out
            FROM users WHERE id = ? LIMIT 1
    |] (PG.Only uid)

  where
    toUserAuth (username, email, passwd, lockedOut) =
        UserAuth uid username email (Password $ Text.encodeUtf8 passwd) lockedOut

withConn f = PostgresBackend $ do
  pool <- ask
  liftIO $ withResource pool f

newtype PostgresBackend a = PostgresBackend
    { runPGBackend :: ReaderT (Pool PG.Connection) IO a
    } deriving (Functor, Applicative, Monad, MonadIO)

runPostgresBackend :: MonadIO m
                   => Pool PG.Connection
                   -> PostgresBackend a
                   -> m a
runPostgresBackend pool (PostgresBackend act) =
  liftIO $ runReaderT act pool

instance UserStore PostgresBackend where
  lookupUserById uid = withConn $ \c -> pgLookupUserById c uid
  createUser u e p = withConn $ \c -> pgCreateUser c u e p

