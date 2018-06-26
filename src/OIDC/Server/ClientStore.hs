{-# LANGUAGE FlexibleInstances #-}
module OIDC.Server.ClientStore
  ( HasClientStore(..)
  , lookupClientById
  , ClientStore(..)
  )  where

import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.Reader (ReaderT, ask)
import           OIDC.Types (ClientAuth, ClientId)

newtype ClientStore = ClientStore
  { csLookupClientById :: ClientId -> IO (Maybe ClientAuth)
  }

class MonadIO m => HasClientStore m where
  askClientStore :: m ClientStore

instance MonadIO m => HasClientStore (ReaderT ClientStore m) where
  askClientStore = ask

withClientStore
  :: HasClientStore m
  => (ClientStore -> m b)
  -> m b
withClientStore act = askClientStore >>= act


lookupClientById
  :: HasClientStore m
  => ClientId
  -> m (Maybe ClientAuth)
lookupClientById cid = withClientStore $ \cs ->
  liftIO $ csLookupClientById cs cid
